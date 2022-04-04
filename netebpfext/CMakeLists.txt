# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

wdk_add_driver("NetEbpfExt" WINVER "${EBPFFORWINDOWS_WDK_WINVER}" KMDF "${EBPFFORWINDOWS_WDK_KMDF_VERSION}"
  net_ebpf_ext.h
  net_ebpf_ext.c

  net_ebpf_ext_bind.h
  net_ebpf_ext_bind.c

  net_ebpf_ext_hook_provider.h
  net_ebpf_ext_hook_provider.c

  net_ebpf_ext_prog_info_provider.h
  net_ebpf_ext_prog_info_provider.c

  net_ebpf_ext_xdp.h
  net_ebpf_ext_xdp.c

  net_ebpf_ext_program_info.h
  resource.h
  
  net_ebpf_ext_drv.c
)

target_include_directories("NetEbpfExt" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
)

target_link_directories("NetEbpfExt" PRIVATE
  "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64"
)

target_link_libraries("NetEbpfExt"
  "ebpf_for_windows_common_settings"
  "Ndis.lib"
  "Netio.lib"
  "Fwpkclnt.lib"
  "wdmsec.lib"
)

target_compile_definitions("NetEbpfExt" PRIVATE
  BINARY_COMPATIBLE=0
  NT
  UNICODE
  _UNICODE
  NDIS60
  POOL_NX_OPTIN_AUTO
)

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "NetEbpfExt"
    DESTINATION "drivers"
  )

  install(
    FILES "netebpfext.inf"
    DESTINATION "drivers"
  )
endif()