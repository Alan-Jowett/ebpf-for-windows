# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.22)
project("ebpf-for-windows")

include("cmake/options.cmake")
include("cmake/settings.cmake")
include("cmake/git_commit.cmake")

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/FindWDK/cmake"
)

find_package(WDK REQUIRED)

add_subdirectory("external")
add_subdirectory("rpc_interface")
add_subdirectory("ebpfapi")
add_subdirectory("libs")
add_subdirectory("tools")
add_subdirectory("ebpfsvc")
add_subdirectory("netebpfext")
add_subdirectory("ebpfcore")

if(EBPFFORWINDOWS_ENABLE_TESTS)
  include("CTest")
  enable_testing()

  add_subdirectory("tests")
endif()
