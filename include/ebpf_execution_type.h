// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum _ebpf_execution_type
    {
        EBPF_EXECUTION_ANY,   ///< Execute from native driver (default).
        EBPF_EXECUTION_NATIVE ///< Execute from native driver.
    } ebpf_execution_type_t;

    // Deprecated execution types - kept for API compatibility but not supported.
    // Using these values will result in an error.
#define EBPF_EXECUTION_JIT ((ebpf_execution_type_t)0xFFFF)
#define EBPF_EXECUTION_INTERPRET ((ebpf_execution_type_t)0xFFFE)

#ifdef __cplusplus
}
#endif
