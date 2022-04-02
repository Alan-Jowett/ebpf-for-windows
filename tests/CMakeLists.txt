# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# TODO(Alessandro): This library is duplicated, since we already have one
#                   copy in the /external folder. They are not at the same
#                   version and so for now we have to include this too.
message(WARNING "ebpf-for-windows - Importing duplicated Catch2 dependency")

add_library("nuget_catch2" INTERFACE)
target_include_directories("nuget_catch2" INTERFACE
  "${CMAKE_SOURCE_DIR}/packages/CatchOrg.Catch.2.8.0/lib/native/include"
)

add_library("NuGet::Catch2" ALIAS "nuget_catch2")

# TODO(Alessandro): Missing: sample, sample_ext_app, sample_ebpf_ext,
#                   bpf2c_test_wrapper

add_subdirectory("api_test")
add_subdirectory("libs")
add_subdirectory("bpf2c_tests")
add_subdirectory("client")
add_subdirectory("performance")
add_subdirectory("xdp")
add_subdirectory("unit")
