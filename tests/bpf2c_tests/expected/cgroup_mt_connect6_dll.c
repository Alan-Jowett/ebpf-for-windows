// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_mt_connect6.o

#include "bpf2c.h"

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>

#define metadata_table cgroup_mt_connect6##_metadata_table
extern metadata_table_t metadata_table;

bool APIENTRY
DllMain(_In_ HMODULE hModule, unsigned int ul_reason_for_call, _In_ void* lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) metadata_table_t* get_metadata_table() { return &metadata_table; }

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         27,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "cgroup_.rodata"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

const char cgroup__rodata_initial_data[] = {
    29, 35, 232, 3};

#pragma data_seg(push, "global_variables")
static global_variable_section_t _global_variable_sections[] = {
    {
        .name = "cgroup_.rodata",
        .size = 4,
        .initial_data = &cgroup__rodata_initial_data,
    },
};
#pragma data_seg(pop)

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_t** global_variable_sections, _Out_ size_t* count)
{
    *global_variable_sections = _global_variable_sections;
    *count = 1;
}

static GUID tcp_mt_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID tcp_mt_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t tcp_mt_connect6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
tcp_mt_connect6(void* context)
#line 27 "sample/cgroup_mt_connect6.c"
{
#line 27 "sample/cgroup_mt_connect6.c"
    // Prologue.
#line 27 "sample/cgroup_mt_connect6.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r0 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r1 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r2 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r3 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r4 = 0;
#line 27 "sample/cgroup_mt_connect6.c"
    register uint64_t r10 = 0;

#line 27 "sample/cgroup_mt_connect6.c"
    r1 = (uintptr_t)context;
#line 27 "sample/cgroup_mt_connect6.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=44 imm=0
#line 27 "sample/cgroup_mt_connect6.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 27 "sample/cgroup_mt_connect6.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=21 imm=6
#line 27 "sample/cgroup_mt_connect6.c"
    if (r2 != IMMEDIATE(6)) {
#line 27 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 27 "sample/cgroup_mt_connect6.c"
    }
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 33 "sample/cgroup_mt_connect6.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_LDDW pc=4 dst=r3 src=r2 offset=0 imm=1
#line 33 "sample/cgroup_mt_connect6.c"
    r3 = POINTER(_global_variable_sections[0].address_of_map_value + 0);
    // EBPF_OP_LDXH pc=6 dst=r3 src=r3 offset=0 imm=0
#line 33 "sample/cgroup_mt_connect6.c"
    r3 = *(uint16_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_BE pc=7 dst=r3 src=r0 offset=0 imm=16
#line 33 "sample/cgroup_mt_connect6.c"
    r3 = htobe16((uint16_t)r3);
#line 33 "sample/cgroup_mt_connect6.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_JGT_REG pc=8 dst=r3 src=r2 offset=15 imm=0
#line 33 "sample/cgroup_mt_connect6.c"
    if (r3 > r2) {
#line 33 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 33 "sample/cgroup_mt_connect6.c"
    }
    // EBPF_OP_MOV64_IMM pc=9 dst=r0 src=r0 offset=0 imm=0
#line 33 "sample/cgroup_mt_connect6.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=10 dst=r3 src=r2 offset=0 imm=0
#line 41 "sample/cgroup_mt_connect6.c"
    r3 = r2;
    // EBPF_OP_BE pc=11 dst=r3 src=r0 offset=0 imm=16
#line 41 "sample/cgroup_mt_connect6.c"
    r3 = htobe16((uint16_t)r3);
#line 41 "sample/cgroup_mt_connect6.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_MOV64_REG pc=12 dst=r4 src=r3 offset=0 imm=0
#line 41 "sample/cgroup_mt_connect6.c"
    r4 = r3;
    // EBPF_OP_MOD64_IMM pc=13 dst=r4 src=r0 offset=0 imm=3
#line 41 "sample/cgroup_mt_connect6.c"
    r4 = IMMEDIATE(3) ? (r4 % IMMEDIATE(3)) : r4;
    // EBPF_OP_JEQ_IMM pc=14 dst=r4 src=r0 offset=9 imm=0
#line 41 "sample/cgroup_mt_connect6.c"
    if (r4 == IMMEDIATE(0)) {
#line 41 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 41 "sample/cgroup_mt_connect6.c"
    }
    // EBPF_OP_AND64_IMM pc=15 dst=r3 src=r0 offset=0 imm=1
#line 41 "sample/cgroup_mt_connect6.c"
    r3 &= IMMEDIATE(1);
    // EBPF_OP_MOV64_IMM pc=16 dst=r0 src=r0 offset=0 imm=1
#line 41 "sample/cgroup_mt_connect6.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=17 dst=r3 src=r0 offset=6 imm=0
#line 46 "sample/cgroup_mt_connect6.c"
    if (r3 == IMMEDIATE(0)) {
#line 46 "sample/cgroup_mt_connect6.c"
        goto label_1;
#line 46 "sample/cgroup_mt_connect6.c"
    }
    // EBPF_OP_LDDW pc=18 dst=r3 src=r2 offset=0 imm=1
#line 54 "sample/cgroup_mt_connect6.c"
    r3 = POINTER(_global_variable_sections[0].address_of_map_value + 2);
    // EBPF_OP_LDXH pc=20 dst=r3 src=r3 offset=0 imm=0
#line 54 "sample/cgroup_mt_connect6.c"
    r3 = *(uint16_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_BE pc=21 dst=r3 src=r0 offset=0 imm=16
#line 54 "sample/cgroup_mt_connect6.c"
    r3 = htobe16((uint16_t)r3);
#line 54 "sample/cgroup_mt_connect6.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_ADD64_REG pc=22 dst=r3 src=r2 offset=0 imm=0
#line 54 "sample/cgroup_mt_connect6.c"
    r3 += r2;
    // EBPF_OP_STXH pc=23 dst=r1 src=r3 offset=40 imm=0
#line 54 "sample/cgroup_mt_connect6.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(40)) = (uint16_t)r3;
label_1:
    // EBPF_OP_EXIT pc=24 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/cgroup_mt_connect6.c"
    return r0;
#line 27 "sample/cgroup_mt_connect6.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        tcp_mt_connect6,
        "cgroup~1",
        "cgroup/connect6",
        "tcp_mt_connect6",
        tcp_mt_connect6_maps,
        1,
        NULL,
        0,
        25,
        &tcp_mt_connect6_program_type_guid,
        &tcp_mt_connect6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_mt_connect6_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
