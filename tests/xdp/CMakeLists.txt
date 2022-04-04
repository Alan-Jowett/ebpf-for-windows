# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("xdp_tests"
  xdp_tests.cpp
)

target_include_directories("xdp_tests" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tests/sample"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
)

target_link_libraries("xdp_tests" PRIVATE
  "ebpf_for_windows_common_settings"
  "common_tests"
  "EbpfApi"
  "test_util"
  "ws2_32.lib"
)

target_compile_definitions("xdp_tests" PRIVATE
  _CONSOLE
  _WINSOCK_DEPRECATED_NO_WARNINGS
)

# This test is using the wrong include header for Catch2; copy the
# file from the external ebpf-verifier project
message(WARNING "ebpf-for-windows - Unit test xdp_tests uses a non-standard Catch2 include path")

configure_file(
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/external/catch.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/catch2/catch.hpp"
)

target_include_directories("xdp_tests" PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}"
)

add_test(
  NAME "xdp_tests"
  COMMAND "xdp_tests"
)
