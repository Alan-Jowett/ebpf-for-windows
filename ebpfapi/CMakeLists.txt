# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("EbpfApi" SHARED
  Source.def

  pch.h
  resource.h

  dllmain.cpp
  rpc_client.cpp

  ../libs/thunk/windows/platform.cpp
  ../resource/ebpf_resource.rc
)

target_include_directories("EbpfApi" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries("EbpfApi" PRIVATE
  "ebpf_for_windows_cxx_settings"
  "api"
  "api_common"
  "external::ebpfverifier"
  "platform_user"
  "ubpf_user"
  "rpc_interface"
  "git_commit_id"
  "bpf2c_driver"
  "Mincore.lib"
)

target_compile_definitions("EbpfApi" PRIVATE
  UNICODE
  EBPFAPI_EXPORTS
  _WINDOWS
  _USRDLL
)
