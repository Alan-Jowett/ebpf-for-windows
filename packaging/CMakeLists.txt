# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.22)
project("ebpf-for-windows")

set(EBPFFORWINDOWS_PROGRAM_DATA "" CACHE PATH "Path containing program data")
if(EBPFFORWINDOWS_PROGRAM_DATA STREQUAL "")
  message(FATAL_ERROR "ebpf-for-windows Invalid program data path")
endif()

if(NOT CPACK_GENERATOR)
  message(FATAL_ERROR "ebpf-for-windows - No generator selected")
endif()

set(CPACK_PACKAGE_VERSION "" CACHE PATH "Package version")
if(EBPFFORWINDOWS_VERSION STREQUAL "")
  message(FATAL_ERROR "ebpf-for-windows - No version has been set")
endif()

set(CPACK_PACKAGE_VERSION "${EBPFFORWINDOWS_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "eBPF implementation that runs on top of Windows.")
set(CPACK_PACKAGE_NAME "${CMAKE_PROJECT_NAME}")
set(CPACK_PACKAGE_VENDOR "Microsoft")
set(CPACK_PACKAGE_CONTACT "opencode@microsoft.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/microsoft/ebpf-for-windows")
set(CPACK_PACKAGE_RELOCATABLE ON)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/../LICENSE.txt")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")

set(base_data_path "${EBPFFORWINDOWS_PROGRAM_DATA}")

install(
  FILES
    "${EBPFFORWINDOWS_PROGRAM_DATA}/bpftool.exe"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/EbpfApi.dll"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpfnetsh.dll"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/bpf2c.exe"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpfsvc.exe"

  DESTINATION
    "."

  COMPONENT
    "eBPF"
)

install(
  FILES
    "${EBPFFORWINDOWS_PROGRAM_DATA}/drivers/NetEbpfExt.sys"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/drivers/netebpfext.inf"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/drivers/EbpfCore.sys"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/drivers/EbpfCore.inf"

  DESTINATION
    "drivers"

  COMPONENT
    "eBPF"
)

install(
  FILES
    "${EBPFFORWINDOWS_PROGRAM_DATA}/scripts/install-ebpf.bat"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/scripts/uninstall-ebpf.bat"

  DESTINATION
    "scripts"

  COMPONENT
    "eBPF"
)

if(CPACK_GENERATOR STREQUAL "WIX")
  set(CPACK_WIX_UPGRADE_GUID "b6bcacb1-c872-4159-abcb-43a50668056c")
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "${CMAKE_PROJECT_NAME}")
  set(CPACK_WIX_EXTENSIONS "WixUtilExtension")
endif()

include(CPack)

cpack_add_component("eBPF"
  DISPLAY_NAME "Standard installation"
  REQUIRED
)
