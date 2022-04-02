# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

option(EBPFFORWINDOWS_ENABLE_TESTS "Set to true to enable tests" true)

set(EBPFFORWINDOWS_WDK_WINVER "0x0A00" CACHE STRING "WINVER value passed to the Windows Driver Kit. Defaults to Windows 10 (0x0A00)")
set(EBPFFORWINDOWS_WDK_KMDF_VERSION "1.15" CACHE STRING "KMDF version used for drivers. Defaults to 1.15")