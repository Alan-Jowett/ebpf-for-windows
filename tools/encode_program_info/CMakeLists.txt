# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("encode_program_info"
  encode_program_info.cpp
)

target_include_directories("encode_program_info" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/netebpfext"
)

target_link_libraries("encode_program_info" PRIVATE
  "ebpf_for_windows_common_settings"
  "execution_context_user"
  "platform_user"
  "Kernel32.lib"
  "Mincore.lib"
)

target_compile_definitions("encode_program_info" PRIVATE
  _CONSOLE
)

# Now call the program to generate our include header
set(ebpf_bind_program_data_name "ebpf_bind_program_data.h")
set(ebpf_bind_program_data_path "${CMAKE_CURRENT_BINARY_DIR}/${ebpf_bind_program_data_name}")

add_custom_command(
  OUTPUT "${ebpf_bind_program_data_path}"
  COMMAND "encode_program_info"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
  COMMENT "ebpf-for-windows - Generating: ${ebpf_bind_program_data_name}"
  VERBATIM
)

add_custom_target("ebpf_bind_program_data_builder"
  DEPENDS "${ebpf_bind_program_data_path}"
)

add_library("ebpf_bind_program_data" INTERFACE)
add_dependencies("ebpf_bind_program_data"
  "ebpf_bind_program_data_builder"
)

target_include_directories("ebpf_bind_program_data" INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)
