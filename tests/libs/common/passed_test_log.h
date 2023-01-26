// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "catch_wrapper.hpp"

#include <windows.h>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <fstream>
#include <iostream>

extern thread_local bool ebpf_enable_memory_tests;

/**
 * @brief A Catch2 reporter that logs the name of each test that passes.
 * This is used to generate a list of tests that passed in the last run in a
 * file that can be used to filter the set of tests that are run in the next
 * run. This is consumed by the Test-LowMemory.ps1 script.
 */
class _passed_test_log : public Catch::EventListenerBase
{
  public:
    using Catch::EventListenerBase::EventListenerBase;

    // Log failed tests.
    void
    testCaseEnded(Catch::TestCaseStats const& testCaseStats) override
    {
        assert(!ebpf_enable_memory_tests);
        if (!passed_tests) {
            char process_name[MAX_PATH];
            GetModuleFileNameA(nullptr, process_name, MAX_PATH);
            std::string log_file = process_name;
            log_file += ".passed.log";
            passed_tests.open(log_file, std::ios::app);
        }
        if (testCaseStats.totals.assertions.failed == 0) {
            passed_tests << testCaseStats.testInfo->name << std::endl;
            passed_tests.flush();
        }
    }

  private:
    static std::ofstream passed_tests;
};

std::ofstream _passed_test_log::passed_tests;
