// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_NAMESPACE

#include "ebpf_epoch.h"
#include "ebpf_hash_table.h"
#include "ebpf_namespace.h"
#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

// Local definition of null GUID to avoid redefinition warnings
static const GUID _ebpf_null_guid = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

// Hash table to track namespaces per process.
static ebpf_hash_table_t* _ebpf_namespace_table = NULL;

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_initiate()
{
    ebpf_result_t return_value;

    ebpf_hash_table_creation_options_t options = {0};
    options.key_size = sizeof(uint64_t);
    options.value_size = sizeof(GUID);
    options.allocate = ebpf_epoch_allocate_with_tag;
    options.free = ebpf_epoch_free;
    options.minimum_bucket_count = 16;

    return_value = ebpf_hash_table_create(&_ebpf_namespace_table, &options);

    return return_value;
}

void
ebpf_namespace_terminate()
{
    ebpf_hash_table_destroy(_ebpf_namespace_table);
    _ebpf_namespace_table = NULL;
}

GUID
ebpf_namespace_get_current()
{
    ebpf_result_t result;
    uint64_t process_start_key;
    GUID* namespace_ptr = NULL;
    GUID namespace = _ebpf_null_guid;

    if (_ebpf_namespace_table == NULL) {
        return _ebpf_null_guid;
    }

    process_start_key = ebpf_platform_get_process_start_key();

    result = ebpf_hash_table_find(_ebpf_namespace_table, (const uint8_t*)&process_start_key, (uint8_t**)&namespace_ptr);
    if (result == EBPF_SUCCESS && namespace_ptr != NULL) {
        namespace = *namespace_ptr;
    }

    ebpf_assert(result == EBPF_SUCCESS);

    return namespace;
}

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_set_current(_In_ const GUID* namespace_guid)
{
    ebpf_result_t result;
    uint64_t process_start_key;
    GUID* existing_namespace = NULL;

    if (_ebpf_namespace_table == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (namespace_guid == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    process_start_key = ebpf_platform_get_process_start_key();

    // Entry should exist (was added during process attach)
    result =
        ebpf_hash_table_find(_ebpf_namespace_table, (const uint8_t*)&process_start_key, (uint8_t**)&existing_namespace);
    ebpf_assert(result == EBPF_SUCCESS);
    if (result == EBPF_SUCCESS) {
        // Update existing entry
        *existing_namespace = *namespace_guid;
        result = EBPF_SUCCESS;
    }

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_process_attach()
{
    uint64_t process_start_key;
    process_start_key = ebpf_platform_get_process_start_key();
    return ebpf_hash_table_update(
        _ebpf_namespace_table,
        (const uint8_t*)&process_start_key,
        (const uint8_t*)&_ebpf_null_guid,
        EBPF_HASH_TABLE_OPERATION_INSERT);
}

void
ebpf_namespace_process_detach()
{
    uint64_t process_start_key;
    process_start_key = ebpf_platform_get_process_start_key();
    ebpf_assert_success(ebpf_hash_table_delete(_ebpf_namespace_table, (const uint8_t*)&process_start_key));
}