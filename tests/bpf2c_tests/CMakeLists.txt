# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("bpf2c_tests"
  ../../tools/bpf2c/btf.h

  ../../tools/bpf2c/bpf_code_generator.h
  ../../tools/bpf2c/bpf_code_generator.cpp

  ../../tools/bpf2c/btf_parser.h
  ../../tools/bpf2c/btf_parser.cpp

  raw_bpf.cpp
)

target_include_directories("bpf2c_tests" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tools/bpf2c"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/external/ELFIO"
)

target_link_libraries("bpf2c_tests" PRIVATE
  "ebpf_for_windows_common_settings"
)

target_compile_definitions("bpf2c_tests" PRIVATE
  _CONSOLE
)

target_compile_options("bpf2c_tests" PRIVATE
  "/WX-"
)

# This test is using the wrong include header for Catch2; copy the
# file from the external ebpf-verifier project
message(WARNING "ebpf-for-windows - Unit test bpf2c_tests uses a non-standard Catch2 include path")

configure_file(
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/external/catch.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/catch2/catch.hpp"
)

target_include_directories("bpf2c_tests" PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}"
)

add_test(
  NAME "bpf2c_tests"
  COMMAND "bpf2c_tests"
)
