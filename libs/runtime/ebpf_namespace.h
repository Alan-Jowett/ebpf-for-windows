// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Initialize the namespace tracking system.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_namespace_initiate();

    /**
     * @brief Terminate the namespace tracking system.
     */
    void
    ebpf_namespace_terminate();

    /**
     * @brief Get the current namespace for the calling process.
     *
     * @return The namespace GUID for the current process, or GUID_NULL if not set.
     */
    GUID
    ebpf_namespace_get_current();

    /**
     * @brief Set the namespace for the calling process.
     *
     * @param[in] namespace_guid The namespace GUID to set for the current process.
     * @return EBPF_SUCCESS on success, error code on failure.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_namespace_set_current(_In_ const GUID* namespace_guid);

    /**
     * @brief On process attach, create the namespace entry for this process.
     *
     * @return EBPF_SUCCESS on success, error code on failure.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_namespace_process_attach();

    /**
     * @brief On process detach, delete the namespace entry for this process.
     */
    void
    ebpf_namespace_process_detach();

#ifdef __cplusplus
}
#endif