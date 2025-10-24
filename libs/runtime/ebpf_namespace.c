// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_NAMESPACE

#include "ebpf_hash_table.h"
#include "ebpf_namespace.h"
#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

#ifndef GUID_NULL
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

// Structure to track namespace per process.
typedef struct _ebpf_namespace_entry
{
    uint64_t process_start_key; ///< Process start key as the hash table key.
    GUID namespace;             ///< The namespace GUID for this process.
} ebpf_namespace_entry_t;

// Hash table to track namespaces per process.
static ebpf_hash_table_t* _ebpf_namespace_table = NULL;

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_initiate()
{
    ebpf_result_t return_value;

    return_value = ebpf_hash_table_create(
        &_ebpf_namespace_table, ebpf_allocate, ebpf_free, sizeof(uint64_t), sizeof(ebpf_namespace_entry_t), NULL, NULL);

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
    ebpf_namespace_entry_t* entry = NULL;
    GUID namespace = GUID_NULL;

    if (_ebpf_namespace_table == NULL) {
        return GUID_NULL;
    }

    process_start_key = ebpf_platform_get_process_start_key();

    result = ebpf_hash_table_find(_ebpf_namespace_table, (const uint8_t*)&process_start_key, (uint8_t**)&entry);
    if (result == EBPF_SUCCESS && entry != NULL) {
        namespace = entry->namespace;
    }

    return namespace;
}

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_set_current(_In_ const GUID* namespace_guid)
{
    ebpf_result_t result;
    uint64_t process_start_key;
    ebpf_namespace_entry_t entry = {0};
    ebpf_namespace_entry_t* existing_entry = NULL;

    if (_ebpf_namespace_table == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (namespace_guid == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    process_start_key = ebpf_platform_get_process_start_key();
    entry.process_start_key = process_start_key;
    entry.namespace = *namespace_guid;

    // Check if entry already exists
    result =
        ebpf_hash_table_find(_ebpf_namespace_table, (const uint8_t*)&process_start_key, (uint8_t**)&existing_entry);
    if (result == EBPF_SUCCESS) {
        // Update existing entry
        existing_entry->namespace = *namespace_guid;
        result = EBPF_SUCCESS;
    } else {
        // Insert new entry
        result = ebpf_hash_table_update(
            _ebpf_namespace_table,
            (const uint8_t*)&process_start_key,
            (const uint8_t*)&entry,
            EBPF_HASH_TABLE_OPERATION_INSERT);
    }

    return result;
}