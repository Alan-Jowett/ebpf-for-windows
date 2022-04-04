# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(execution_context_sources
  ebpf_core.h
  ebpf_core.c

  ebpf_link.h
  ebpf_link.c

  ebpf_maps.h
  ebpf_maps.c

  ebpf_native.h
  ebpf_native.c

  ebpf_program.h
  ebpf_program.c

  ebpf_protocol.h
  ebpf_general_helpers.c
)

set(execution_context_include_dirs
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
)

#
# execution_context_user
#

add_library("execution_context_user" STATIC
  ${execution_context_sources}
  user/pch.h
)

target_include_directories("execution_context_user" PRIVATE
  ${execution_context_include_dirs}
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
)

target_link_libraries("execution_context_user" PRIVATE
  "ebpf_for_windows_common_settings"
)

target_compile_definitions("execution_context_user" PRIVATE
  _LIB
)

#
# execution_context_kernel
#

wdk_add_library("execution_context_kernel" STATIC WINVER "${EBPFFORWINDOWS_WDK_WINVER}"
  ${execution_context_sources}
  kernel/pch.h
)

target_include_directories("execution_context_kernel" PRIVATE
  ${execution_context_include_dirs}
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
)

target_link_libraries("execution_context_kernel" PRIVATE
  "ebpf_for_windows_common_settings"
)

target_compile_definitions("execution_context_kernel" PRIVATE
  WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP
  WINAPI_PARTITION_DESKTOP=1
  WINAPI_PARTITION_SYSTEM=1
  WINAPI_PARTITION_APP=1
  WINAPI_PARTITION_PC_APP=1
  _NO_CRT_STDIO_INLINE=1
)
