# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("api_common" STATIC
  windows_helpers.cpp

  map_descriptors.hpp
  map_descriptors.cpp

  windows_platform_common.hpp
  windows_platform_common.cpp

  api_common.hpp
  api_common.cpp

  device_helper.hpp
  device_helper.cpp
)

target_include_directories("api_common" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
)

target_link_libraries("api_common" PRIVATE
  "ebpf_for_windows_cxx_settings"
  "ebpf_bind_program_data"
  "external::boost"
  "external::ebpfverifier"
)

target_compile_definitions("api_common" PRIVATE
  _UNICODE
  _WINDOWS
  _USRDLL
)
