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

#ifdef __cplusplus
}
#endif
