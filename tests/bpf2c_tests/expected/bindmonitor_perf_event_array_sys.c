// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_perf_event_array.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table bindmonitor_perf_event_array##_metadata_table

static GUID _bpf2c_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                             0xc847aac8,
                             0xa6f2,
                             0x4b53,
                             {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};
static NPI_MODULEID _bpf2c_module_id = {sizeof(_bpf2c_module_id), MIT_GUID, {0}};
static HANDLE _bpf2c_nmr_client_handle;
static HANDLE _bpf2c_nmr_provider_handle;
extern metadata_table_t metadata_table;

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

static NTSTATUS
_bpf2c_npi_client_detach_provider(_In_ void* client_binding_context);

static const NPI_CLIENT_CHARACTERISTICS _bpf2c_npi_client_characteristics = {
    0,                                  // Version
    sizeof(NPI_CLIENT_CHARACTERISTICS), // Length
    _bpf2c_npi_client_attach_provider,
    _bpf2c_npi_client_detach_provider,
    NULL,
    {0,                                 // Version
     sizeof(NPI_REGISTRATION_INSTANCE), // Length
     &_bpf2c_npi_id,
     &_bpf2c_module_id,
     0,
     &metadata_table}};

static NTSTATUS
_bpf2c_query_npi_module_id(
    _In_ const wchar_t* value_name,
    unsigned long value_type,
    _In_ const void* value_data,
    unsigned long value_length,
    _Inout_ void* context,
    _Inout_ void* entry_context)
{
    UNREFERENCED_PARAMETER(value_name);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(entry_context);

    if (value_type != REG_BINARY) {
        return STATUS_INVALID_PARAMETER;
    }
    if (value_length != sizeof(_bpf2c_module_id.Guid)) {
        return STATUS_INVALID_PARAMETER;
    }

    memcpy(&_bpf2c_module_id.Guid, value_data, value_length);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    RTL_QUERY_REGISTRY_TABLE query_table[] = {
        {
            NULL,                      // Query routine
            RTL_QUERY_REGISTRY_SUBKEY, // Flags
            L"Parameters",             // Name
            NULL,                      // Entry context
            REG_NONE,                  // Default type
            NULL,                      // Default data
            0,                         // Default length
        },
        {
            _bpf2c_query_npi_module_id,  // Query routine
            RTL_QUERY_REGISTRY_REQUIRED, // Flags
            L"NpiModuleId",              // Name
            NULL,                        // Entry context
            REG_NONE,                    // Default type
            NULL,                        // Default data
            0,                           // Default length
        },
        {0}};

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, registry_path->Buffer, query_table, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = NmrRegisterClient(&_bpf2c_npi_client_characteristics, NULL, &_bpf2c_nmr_client_handle);

Exit:
    if (NT_SUCCESS(status)) {
        driver_object->DriverUnload = DriverUnload;
    }

    return status;
}

void
DriverUnload(_In_ DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = NmrDeregisterClient(_bpf2c_nmr_client_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForClientDeregisterComplete(_bpf2c_nmr_client_handle);
    }
    UNREFERENCED_PARAMETER(driver_object);
}

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    NTSTATUS status = STATUS_SUCCESS;
    void* provider_binding_context = NULL;
    void* provider_dispatch_table = NULL;

    UNREFERENCED_PARAMETER(client_context);
    UNREFERENCED_PARAMETER(provider_registration_instance);

    if (_bpf2c_nmr_provider_handle != NULL) {
        return STATUS_INVALID_PARAMETER;
    }

#pragma warning(push)
#pragma warning( \
    disable : 6387) // Param 3 does not adhere to the specification for the function 'NmrClientAttachProvider'
    // As per MSDN, client dispatch can be NULL, but SAL does not allow it.
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/nf-netioddk-nmrclientattachprovider
    status = NmrClientAttachProvider(
        nmr_binding_handle, client_context, NULL, &provider_binding_context, &provider_dispatch_table);
    if (status != STATUS_SUCCESS) {
        goto Done;
    }
#pragma warning(pop)
    _bpf2c_nmr_provider_handle = nmr_binding_handle;

Done:
    return status;
}

static NTSTATUS
_bpf2c_npi_client_detach_provider(_In_ void* client_binding_context)
{
    _bpf2c_nmr_provider_handle = NULL;
    UNREFERENCED_PARAMETER(client_binding_context);
    return STATUS_SUCCESS;
}

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {0,
     {
         BPF_MAP_TYPE_PERF_EVENT_ARRAY, // Type of map.
         0,                             // Size in bytes of a map key.
         0,                             // Size in bytes of a map value.
         65536,                         // Maximum number of entries allowed in the map.
         0,                             // Inner map index.
         LIBBPF_PIN_NONE,               // Pinning type for the map.
         7,                             // Identifier for a map template.
         0,                             // The id of the inner map template.
     },
     "process_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t bind_monitor_helpers[] = {
    {6, "helper_id_6"},
    {32, "helper_id_32"},
};

static GUID bind_monitor_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID bind_monitor_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t bind_monitor_maps[] = {
    0,
};

#pragma code_seg(push, "bind")
static uint64_t
bind_monitor(void* context, const program_runtime_context_t* runtime_context)
#line 24 "sample/bindmonitor_perf_event_array.c"
{
#line 24 "sample/bindmonitor_perf_event_array.c"
    // Prologue.
#line 24 "sample/bindmonitor_perf_event_array.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r0 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r1 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r2 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r3 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r4 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r5 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r6 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r7 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r8 = 0;
#line 24 "sample/bindmonitor_perf_event_array.c"
    register uint64_t r10 = 0;

#line 24 "sample/bindmonitor_perf_event_array.c"
    r1 = (uintptr_t)context;
#line 24 "sample/bindmonitor_perf_event_array.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 24 "sample/bindmonitor_perf_event_array.c"
    r6 = r1;
    // EBPF_OP_LDXDW pc=1 dst=r8 src=r6 offset=0 imm=0
#line 26 "sample/bindmonitor_perf_event_array.c"
    r8 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_LDXDW pc=2 dst=r7 src=r6 offset=8 imm=0
#line 26 "sample/bindmonitor_perf_event_array.c"
    r7 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_CALL pc=3 dst=r0 src=r0 offset=0 imm=6
#line 28 "sample/bindmonitor_perf_event_array.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 28 "sample/bindmonitor_perf_event_array.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 28 "sample/bindmonitor_perf_event_array.c"
        return 0;
#line 28 "sample/bindmonitor_perf_event_array.c"
    }
    // EBPF_OP_STXW pc=4 dst=r10 src=r0 offset=-4 imm=0
#line 28 "sample/bindmonitor_perf_event_array.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r0;
    // EBPF_OP_LDXW pc=5 dst=r1 src=r6 offset=44 imm=0
#line 29 "sample/bindmonitor_perf_event_array.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=6 dst=r1 src=r0 offset=19 imm=0
#line 29 "sample/bindmonitor_perf_event_array.c"
    if (r1 != IMMEDIATE(0)) {
#line 29 "sample/bindmonitor_perf_event_array.c"
        goto label_1;
#line 29 "sample/bindmonitor_perf_event_array.c"
    }
    // EBPF_OP_LDXDW pc=7 dst=r1 src=r6 offset=8 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=8 dst=r2 src=r6 offset=0 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JGE_REG pc=9 dst=r2 src=r1 offset=16 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    if (r2 >= r1) {
#line 31 "sample/bindmonitor_perf_event_array.c"
        goto label_1;
#line 31 "sample/bindmonitor_perf_event_array.c"
    }
    // EBPF_OP_SUB64_REG pc=10 dst=r7 src=r8 offset=0 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r7 -= r8;
    // EBPF_OP_LSH64_IMM pc=11 dst=r7 src=r0 offset=0 imm=32
#line 31 "sample/bindmonitor_perf_event_array.c"
    r7 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=12 dst=r1 src=r0 offset=0 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r1 = (uint64_t)4503595332403200;
    // EBPF_OP_AND64_REG pc=14 dst=r7 src=r1 offset=0 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r7 &= r1;
    // EBPF_OP_LDDW pc=15 dst=r1 src=r0 offset=0 imm=-1
#line 31 "sample/bindmonitor_perf_event_array.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_OR64_REG pc=17 dst=r7 src=r1 offset=0 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r7 |= r1;
    // EBPF_OP_MOV64_REG pc=18 dst=r4 src=r10 offset=0 imm=0
#line 31 "sample/bindmonitor_perf_event_array.c"
    r4 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r4 src=r0 offset=0 imm=-4
#line 31 "sample/bindmonitor_perf_event_array.c"
    r4 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=20 dst=r1 src=r6 offset=0 imm=0
#line 32 "sample/bindmonitor_perf_event_array.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=21 dst=r2 src=r1 offset=0 imm=1
#line 32 "sample/bindmonitor_perf_event_array.c"
    r2 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=23 dst=r3 src=r7 offset=0 imm=0
#line 32 "sample/bindmonitor_perf_event_array.c"
    r3 = r7;
    // EBPF_OP_MOV64_IMM pc=24 dst=r5 src=r0 offset=0 imm=4
#line 32 "sample/bindmonitor_perf_event_array.c"
    r5 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=32
#line 32 "sample/bindmonitor_perf_event_array.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 32 "sample/bindmonitor_perf_event_array.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 32 "sample/bindmonitor_perf_event_array.c"
        return 0;
#line 32 "sample/bindmonitor_perf_event_array.c"
    }
label_1:
    // EBPF_OP_MOV64_IMM pc=26 dst=r0 src=r0 offset=0 imm=0
#line 39 "sample/bindmonitor_perf_event_array.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=27 dst=r0 src=r0 offset=0 imm=0
#line 39 "sample/bindmonitor_perf_event_array.c"
    return r0;
#line 24 "sample/bindmonitor_perf_event_array.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        bind_monitor,
        "bind",
        "bind",
        "bind_monitor",
        bind_monitor_maps,
        1,
        bind_monitor_helpers,
        2,
        28,
        &bind_monitor_program_type_guid,
        &bind_monitor_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bindmonitor_perf_event_array_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
