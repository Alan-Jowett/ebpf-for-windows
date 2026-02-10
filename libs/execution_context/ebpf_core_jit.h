// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_structs.h"

#ifdef __cplusplus
extern "C"
{
#endif

    // Shared variable between ebpf_core.c and ebpf_core_jit.c, defined in ebpf_core.c.
    extern bool ebpf_platform_hypervisor_code_integrity_enabled;

#define PROTOCOL_NATIVE_MODE 1
#define PROTOCOL_PRIVILEGED_OPERATION 8
#define PROTOCOL_ALL_MODES PROTOCOL_NATIVE_MODE

#ifdef __cplusplus
}
#endif
