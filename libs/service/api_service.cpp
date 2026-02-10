// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "Verifier.h"
#include "api_common.hpp"
#include "api_service.h"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "ebpf_shared_framework.h"
#include "hash.h"
#include "map_descriptors.hpp"
#include "platform.h"
#include "verifier_service.h"
#include "windows_platform.hpp"

#include <format>
#include <map>
#include <set>
#include <softpub.h>
#include <stdexcept>
#include <string>
#include <wintrust.h>

// Include wintrust.lib
#pragma comment(lib, "wintrust.lib")

static bool _ebpf_service_test_signing_enabled = false;
static bool _ebpf_service_hypervisor_kernel_mode_code_enforcement_enabled = false;

class WinVerifyTrustHelper
{
  public:
    WinVerifyTrustHelper(const wchar_t* path)
    {
        win_trust_data.cbStruct = sizeof(WINTRUST_DATA);
        win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        win_trust_data.dwUIChoice = WTD_UI_NONE;
        win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        win_trust_data.dwUnionChoice = WTD_CHOICE_FILE;

        file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
        file_info.pcwszFilePath = path;

        win_trust_data.pFile = &file_info;

        signature_settings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
        signature_settings.dwFlags = WSS_VERIFY_SPECIFIC | WSS_GET_SECONDARY_SIG_COUNT;
        signature_settings.dwIndex = 0;

        win_trust_data.pSignatureSettings = &signature_settings;

        // Query the number of signatures.
        DWORD error = WinVerifyTrust(nullptr, &generic_action_code, &win_trust_data);
        if (error != ERROR_SUCCESS) {
            SetLastError(error);
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WinVerifyTrust);
            clean_up_win_verify_trust();
            throw std::runtime_error("WinVerifyTrust failed");
        }
    }

    ~WinVerifyTrustHelper() { clean_up_win_verify_trust(); }

    DWORD
    cert_count()
    {
        // The number of signatures is stored in signature_settings.cSecondarySigs.
        // The primary signature is always present, so we add 1 to the count.
        return signature_settings.cSecondarySigs + 1;
    }

    CRYPT_PROVIDER_CERT*
    get_cert(DWORD index)
    {
        set_current_certificate_index(index);

        CRYPT_PROVIDER_DATA* provider_data = WTHelperProvDataFromStateData(win_trust_data.hWVTStateData);
        CRYPT_PROVIDER_SGNR* provider_signer = WTHelperGetProvSignerFromChain(provider_data, 0, FALSE, 0);
        CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(provider_signer, 0);

        if (cert == nullptr) {
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WTHelperGetProvCertFromChain);
            throw std::runtime_error("WTHelperGetProvCertFromChain failed");
        }
        return cert;
    }

    CRYPT_PROVIDER_CERT*
    get_root_cert(DWORD index)
    {
        set_current_certificate_index(index);

        // Get the root certificate by using the last certificate in the chain.
        CRYPT_PROVIDER_DATA* provider_data = WTHelperProvDataFromStateData(win_trust_data.hWVTStateData);
        CRYPT_PROVIDER_SGNR* provider_signer = WTHelperGetProvSignerFromChain(provider_data, 0, FALSE, 0);
        DWORD cert_count = provider_signer->csCertChain;
        if (cert_count == 0) {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "No certificates found in chain");
            throw std::runtime_error("No certificates found in chain");
        }
        return WTHelperGetProvCertFromChain(provider_signer, cert_count - 1);
    }

  private:
    void
    clean_up_win_verify_trust()
    {
        if (win_trust_data.hWVTStateData) {
            win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            // Ignore the return value of WinVerifyTrust on close.
            (void)WinVerifyTrust(nullptr, &generic_action_code, &win_trust_data);
            win_trust_data.hWVTStateData = nullptr;
        }
    }

    void
    set_current_certificate_index(DWORD index)
    {
        // Check if the context currently points to the correct index.
        if (signature_settings.dwIndex != index) {
            clean_up_win_verify_trust();

            win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
            win_trust_data.pSignatureSettings->dwIndex = index;

            DWORD error = WinVerifyTrust(nullptr, &generic_action_code, &win_trust_data);
            if (error != ERROR_SUCCESS) {
                SetLastError(error);
                EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WinVerifyTrust);
                throw std::runtime_error("WinVerifyTrust failed");
            }
        }
    }

    GUID generic_action_code = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA win_trust_data = {};
    WINTRUST_FILE_INFO file_info = {};
    WINTRUST_SIGNATURE_SETTINGS signature_settings = {};
};

static std::set<std::string>
_ebpf_extract_eku(_In_ CRYPT_PROVIDER_CERT* cert)
{
    std::set<std::string> eku_set;
    DWORD cb_usage = 0;
    if (!CertGetEnhancedKeyUsage(cert->pCert, 0, nullptr, &cb_usage)) {
        return eku_set;
    }
    std::vector<uint8_t> usage(cb_usage);

    if (!CertGetEnhancedKeyUsage(cert->pCert, 0, reinterpret_cast<PCERT_ENHKEY_USAGE>(usage.data()), &cb_usage)) {
        return eku_set;
    }
    auto pusage = reinterpret_cast<PCERT_ENHKEY_USAGE>(usage.data());
    for (size_t index = 0; index < pusage->cUsageIdentifier; index++) {
        eku_set.insert(pusage->rgpszUsageIdentifier[index]);
    }
    return eku_set;
}

static std::string
_ebpf_extract_subject(_In_ const CRYPT_PROVIDER_CERT* cert)
{
    DWORD name_cb = CertGetNameStringA(cert->pCert, CERT_NAME_RDN_TYPE, 0, nullptr, nullptr, 0);

    if (name_cb == 0) {
        return std::string();
    }

    std::vector<char> subject(name_cb);
    if (CertGetNameStringA(cert->pCert, CERT_NAME_RDN_TYPE, 0, nullptr, subject.data(), name_cb) == 0) {
        return std::string();
    }
    return std::string(subject.data());
}

static std::string
_ebpf_extract_certificate_thumbprint(_In_ const CRYPT_PROVIDER_CERT* cert)
{
    // Note: The thumbprint is the SHA1 hash of the certificate.
    hash_t hash("SHA1");
    auto thumbprint = hash.hash_byte_ranges(
        hash_t::byte_range_t{std::make_tuple(cert->pCert->pbCertEncoded, cert->pCert->cbCertEncoded)});

    std::string thumbprint_string;
    for (const auto& byte : thumbprint) {
        thumbprint_string +=
            std::format("{:02x}", byte); // Convert each byte to a two-digit hexadecimal string and append it.
    }

    return thumbprint_string;
}

_Must_inspect_result_ ebpf_result_t
ebpf_verify_sys_file_signature(
    _In_z_ const wchar_t* file_name,
    _In_z_ const char* subject_name,
    _In_z_ const char* root_certificate_thumbprint,
    size_t eku_count,
    _In_reads_(eku_count) const char** eku_list)
{
    ebpf_result_t result = EBPF_OBJECT_NOT_FOUND;
    EBPF_LOG_ENTRY();
    std::string required_subject(subject_name);
    std::set<std::string> required_eku_set;

    if (_ebpf_service_test_signing_enabled) {
        // Test signing is enabled, so we don't verify the signature.
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

    for (size_t i = 0; i < eku_count; i++) {
        required_eku_set.insert(eku_list[i]);
    }

    try {
        WinVerifyTrustHelper wrapper(file_name);

        for (DWORD i = 0; i < wrapper.cert_count(); i++) {

            std::set<std::string> eku_set = _ebpf_extract_eku(wrapper.get_cert(i));
            std::string thumbprint = _ebpf_extract_certificate_thumbprint(wrapper.get_root_cert(i));
            std::string subject = _ebpf_extract_subject(wrapper.get_cert(i));

            if (thumbprint != root_certificate_thumbprint) {
                EBPF_LOG_MESSAGE_STRING(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_API,
                    "Certificate thumbprint mismatch",
                    thumbprint.c_str());
                continue;
            }

            if (subject != required_subject) {
                EBPF_LOG_MESSAGE_STRING(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_API,
                    "Certificate subject mismatch",
                    subject.c_str());
                continue;
            }

            std::set<std::string> eku_intersection;
            std::set_intersection(
                eku_set.begin(),
                eku_set.end(),
                required_eku_set.begin(),
                required_eku_set.end(),
                std::inserter(eku_intersection, eku_intersection.begin()));

            if (eku_intersection.size() != required_eku_set.size()) {
                EBPF_LOG_MESSAGE_STRING(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_API,
                    "Certificate EKU mismatch",
                    "Required EKUs not found in certificate");
                continue;
            }

            // The certificate is valid and has the required EKUs.
            result = EBPF_SUCCESS;
            break;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        EBPF_LOG_MESSAGE_ERROR(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_API,
            "Memory allocation failed during signature verification",
            result);
    } catch (const std::runtime_error&) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WinVerifyTrust);
    }

    EBPF_RETURN_RESULT(result);
}

static const char* _ebpf_required_subject = EBPF_REQUIRED_SUBJECT;
static const char* _ebpf_required_root_certificate_thumbprint = EBPF_REQUIRED_ROOT_CERTIFICATE_THUMBPRINT;
static const char* _ebpf_required_eku_list[] = {
    EBPF_CODE_SIGNING_EKU,
    EBPF_VERIFICATION_EKU,
};

_Must_inspect_result_ ebpf_result_t
ebpf_verify_signature_and_open_file(_In_z_ const char* file_path, _Out_ HANDLE* file_handle) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    try {
        std::wstring file_path_wide;
        int file_path_length = MultiByteToWideChar(CP_UTF8, 0, file_path, -1, nullptr, 0);
        if (file_path_length <= 0) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            EBPF_LOG_MESSAGE_ERROR(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "MultiByteToWideChar failed", result);
            EBPF_RETURN_RESULT(result);
        }
        file_path_wide.resize(file_path_length);

        if (MultiByteToWideChar(CP_UTF8, 0, file_path, -1, file_path_wide.data(), file_path_length) <= 0) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            EBPF_LOG_MESSAGE_ERROR(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "MultiByteToWideChar failed", result);
            EBPF_RETURN_RESULT(result);
        }

        *file_handle = CreateFileW(
            file_path_wide.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
            nullptr);

        if (*file_handle == INVALID_HANDLE_VALUE) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "CreateFileW failed", result);
            EBPF_RETURN_RESULT(result);
        }

        // Note: Signature verification is done after the file is opened to ensure that the file exists and can not be
        // modified.
        result = ebpf_verify_sys_file_signature(
            file_path_wide.c_str(),
            _ebpf_required_subject,
            _ebpf_required_root_certificate_thumbprint,
            sizeof(_ebpf_required_eku_list) / sizeof(_ebpf_required_eku_list[0]),
            _ebpf_required_eku_list);

        EBPF_RETURN_RESULT(result);
    } catch (const std::bad_alloc&) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    } catch (const std::exception&) {
        EBPF_RETURN_RESULT(EBPF_FAILED);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_authorize_native_module(_In_ const GUID* module_id, _In_ HANDLE native_image_handle) noexcept
{
    EBPF_LOG_ENTRY();

    ebpf_result_t result = EBPF_SUCCESS;
    HANDLE file_mapping_handle = NULL;
    void* file_mapping_view = nullptr;
    size_t file_size = 0;
    ebpf_operation_authorize_native_module_request_t request;
    uint32_t error = ERROR_SUCCESS;

    file_mapping_handle = CreateFileMappingW(native_image_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if (file_mapping_handle == NULL) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        EBPF_LOG_MESSAGE_ERROR(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "CreateFileMappingW failed", result);
        goto Done;
    }

    file_size = GetFileSize(native_image_handle, nullptr);

    if (file_size == INVALID_FILE_SIZE) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "GetFileSize failed", result);
        goto Done;
    }

    file_mapping_view = MapViewOfFile(file_mapping_handle, FILE_MAP_READ, 0, 0, file_size);

    if (file_mapping_view == nullptr) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "MapViewOfFile failed", result);
        goto Done;
    }

    try {
        // Compute the SHA256 hash of the file.
        hash_t hash("SHA256");
        auto sha256_hash = hash.hash_byte_ranges({{(uint8_t*)file_mapping_view, file_size}});
        std::copy(sha256_hash.begin(), sha256_hash.end(), request.module_hash);
        request.header.id = ebpf_operation_id_t::EBPF_OPERATION_AUTHORIZE_NATIVE_MODULE;
        request.header.length = static_cast<uint16_t>(sizeof(request));
        request.module_id = *module_id;
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    error = invoke_ioctl(request);
    if (error != ERROR_SUCCESS) {
        result = win32_error_code_to_ebpf_result(error);
        EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "invoke_ioctl failed", result);
        goto Done;
    }

Done:
    if (file_mapping_view) {
        UnmapViewOfFile(file_mapping_view);
    }
    if (file_mapping_handle != INVALID_HANDLE_VALUE && file_mapping_handle != 0) {
        CloseHandle(file_mapping_handle);
    }

    EBPF_RETURN_RESULT(result);
}

/**
 * @brief Initialize the test signing state.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT The reply from the driver was invalid.
 * @retval EBPF_NO_MEMORY Insufficient memory to complete the operation.
 */
static _Must_inspect_result_ ebpf_result_t
_initialize_test_signing_state()
{
    _ebpf_service_test_signing_enabled = false;
    _ebpf_service_hypervisor_kernel_mode_code_enforcement_enabled = false;

    ebpf_operation_get_code_integrity_state_request_t request{
        sizeof(ebpf_operation_get_code_integrity_state_request_t),
        ebpf_operation_id_t::EBPF_OPERATION_GET_CODE_INTEGRITY_STATE};
    ebpf_operation_get_code_integrity_state_reply_t reply;

    uint32_t error = invoke_ioctl(request, reply);
    if (error != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(error);
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_CODE_INTEGRITY_STATE) {
        return EBPF_INVALID_ARGUMENT;
    }

    _ebpf_service_test_signing_enabled = reply.test_signing_enabled;
    _ebpf_service_hypervisor_kernel_mode_code_enforcement_enabled = reply.hypervisor_code_integrity_enabled;

    return EBPF_SUCCESS;
}

uint32_t
ebpf_service_initialize() noexcept
{
    // This is best effort. If device handle does not initialize,
    // it will be re-attempted before an IOCTL call is made.
    // This is needed to ensure the service can successfully start
    // even if the driver is not installed.
    (void)initialize_async_device_handle();

    ebpf_result_t result = _initialize_test_signing_state();
    if (result != EBPF_SUCCESS) {
        switch (result) {
        case EBPF_NO_MEMORY:
            return ERROR_NOT_ENOUGH_MEMORY;
        case EBPF_INVALID_ARGUMENT:
            return ERROR_INVALID_PARAMETER;
        default:
            return ERROR_NOT_SUPPORTED;
        }
    }

    return ERROR_SUCCESS;
}

void
ebpf_service_cleanup() noexcept
{
    clean_up_async_device_handle();
}
