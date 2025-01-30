// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

static const volatile int global_var = 10;
static volatile int global_var2 = 20;
static volatile int global_var3;
static volatile int global_var4 = 40;

SEC("sample_ext")
int
GlobalVariableTest(sample_program_context_t* ctx)
{
    global_var3 = global_var + global_var2;
    global_var3 += global_var4;
    return 0;
}
