# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("ebpf_for_windows_common_settings" INTERFACE)
target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
  $<$<CONFIG:Release>:_DEBUG>
  $<$<CONFIG:Debug>:NDEBUG>
)

if(EBPFFORWINDOWS_ENABLE_DISABLE_EBPF_INTERPRETER)
  target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
    CONFIG_BPF_JIT_ALWAYS_ON=1
  )
endif()
