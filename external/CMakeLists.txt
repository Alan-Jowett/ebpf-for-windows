# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_subdirectory("ebpf-verifier" EXCLUDE_FROM_ALL)
add_subdirectory("Catch2" EXCLUDE_FROM_ALL)

# Special target that we can link to external dependencies
# to override build settings
add_library("ebpf_for_windows_external_settings" INTERFACE)
target_compile_options("ebpf_for_windows_external_settings" INTERFACE
  "/w"
)

target_compile_definitions("ebpf_for_windows_external_settings" INTERFACE
  "_CRT_SECURE_NO_WARNINGS"
  "_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS"
)

#
# Catch2
#

target_link_libraries("Catch2" PRIVATE
  "ebpf_for_windows_external_settings"
)

#
# ebpfverifier
#

target_link_libraries("ebpfverifier" PRIVATE
  "ebpf_for_windows_external_settings"
)

# Fix missing dependency between ebpfverifier and yaml-cpp
add_dependencies("ebpfverifier"
  "yaml-cpp"
)

# Fix missing INTERFACE include directories
target_include_directories("ebpfverifier" INTERFACE
  ebpf-verifier/src
  ebpf-verifier/external/elfio
)

add_library("external::ebpfverifier" ALIAS "ebpfverifier")

#
# boost (downloaded by ebpfverifier)
#

add_library("boost" INTERFACE)
target_include_directories("boost" INTERFACE
  "${CMAKE_BINARY_DIR}/packages/boost/lib/native/include"
)

add_library("external::boost" ALIAS "boost")

#
# bpftool
#

add_executable("bpftool"
  bpftool/src/common.c
  bpftool/libbpf/src/hashmap.c
  bpftool/src/json_writer.c
  bpftool/src/link.c
  bpftool/src/main.c
  bpftool/src/map.c
  bpftool/src/prog.c
  win-c/source/getopt.c
)

target_include_directories("bpftool" PRIVATE
"${CMAKE_SOURCE_DIR}/include"
"${CMAKE_SOURCE_DIR}/external/bpftool/libbpf/src"
"${CMAKE_SOURCE_DIR}/external/bpftool/libbpf/include"
"${CMAKE_SOURCE_DIR}/external/win-c/include"
)

target_compile_definitions("bpftool" PRIVATE
  BPFTOOL_VERSION="0.1"
  _CONSOLE
)

target_link_libraries("bpftool" PRIVATE
  "ebpf_for_windows_external_settings"
  "ebpf_for_windows_common_settings"
  "EbpfApi"
)

add_executable("external::bpftool" ALIAS "bpftool")

codeSign("bpftool")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "bpftool"
    DESTINATION "."
  )
endif()