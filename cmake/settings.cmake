# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("ebpf_for_windows_common_settings" INTERFACE)
target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
  $<$<CONFIG:Release>:_DEBUG>
  $<$<CONFIG:Debug>:NDEBUG>
)

add_library("ebpf_for_windows_cxx_settings" INTERFACE)
target_link_libraries("ebpf_for_windows_cxx_settings" INTERFACE
  "ebpf_for_windows_common_settings"
)

add_library("ebpf_for_windows_c_settings" INTERFACE)
target_link_libraries("ebpf_for_windows_c_settings" INTERFACE
  "ebpf_for_windows_common_settings"
)
