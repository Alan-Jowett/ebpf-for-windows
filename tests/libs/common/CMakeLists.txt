# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("common_tests" STATIC
  common_tests.cpp
  ../../../libs/thunk/windows/platform.cpp
)

target_include_directories("common_tests" PRIVATE
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/tests/util"
  "${CMAKE_SOURCE_DIR}/tests/sample"
)

target_link_libraries("common_tests" PRIVATE
  "ebpf_for_windows_common_settings"
  "Catch2::Catch2"
)

target_compile_definitions("common_tests" PRIVATE
  _UNICODE
  _CONSOLE
)
