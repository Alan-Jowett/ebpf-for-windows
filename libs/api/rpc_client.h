// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "rpc_interface_h.h"

#include <rpc.h>

RPC_STATUS
clean_up_rpc_binding(void);

_Must_inspect_result_ ebpf_result_t
ebpf_rpc_authorize_native_module(_In_ const GUID* module_id, _In_z_ const char* image_path) noexcept;