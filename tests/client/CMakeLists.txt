# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("ebpf_client"
  main.cpp

  ../../libs/thunk/windows/platform.cpp

  ../../libs/api/rpc_client.h
  ../../ebpfapi/rpc_client.cpp
)

target_include_directories("ebpf_client" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/rpc_interface"
  "${CMAKE_SOURCE_DIR}/ebpfsvc"
)

target_link_libraries("ebpf_client" PRIVATE
  "ebpf_for_windows_cxx_settings"
  "external::ebpfverifier"
  "api"
  "api_common"
  "platform_user"
  "service"
  "test_util"
  "ubpf_user"
  "Catch2::Catch2WithMain"
  "external::boost"
  "Mincore.lib"
  "rpc_interface"
)

target_compile_definitions("ebpf_client" PRIVATE
  _UNICODE
  _CONSOLE
)

add_test(
  NAME "ebpf_client"
  COMMAND "ebpf_client"
)
