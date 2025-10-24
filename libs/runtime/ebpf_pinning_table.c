// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// The pinning table stores ebpf_pinning_entry_t objects in an ebpf_hash_table_t, which is designed to store fixed
// size keys and values. The pinning table uses cxplat_utf8_string_t as the key for this table, which is a variable
// sized structure with embedded pointers. As a result, cxplat_utf8_string_t structures are not directly comparable.
// To handle this case, the ebpf_hash_table_t exposes an extract method, that accepts a key and returns
// a pointer to data that can be compared or hashed. The ebpf_hash_table_t is initialized to use cxplat_utf8_string_t*
// as keys and ebpf_pinning_entry_t* as values.
// Insertion - The key is a pointer to the cxplat_utf8_string_t embedded in the ebpf_pinning_entry_t and the value is
// a pointer to the ebpf_pinning_entry_t object.
// Find/Delete - The key is a pointer to an cxplat_utf8_string_t that contains the string to search for.
// Find returns a pointer to the ebpf_pinning_entry_t object. Comparison is done based on the value pointed to by the
// key. Delete erases the entry from the ebpf_hash_table_t, but doesn't free the memory associated with the
// ebpf_pinning_entry_t.

#define EBPF_FILE_ID EBPF_FILE_ID_PINNING_TABLE

#include "ebpf_core_structs.h"
#include "ebpf_hash_table.h"
#include "ebpf_namespace.h"
#include "ebpf_object.h"
#include "ebpf_pinning_table.h"
#include "ebpf_tracelog.h"

#define EBPF_PINNING_TABLE_BUCKET_COUNT 64

typedef struct _ebpf_pinning_table
{
    _Guarded_by_(lock) ebpf_hash_table_t* hash_table;
    ebpf_lock_t lock;
} ebpf_pinning_table_t;

/**
 * @brief Internal composite key structure that includes both namespace and path for proper isolation
 * This is used internally by the hash table but not exposed in the public API
 */
typedef struct _ebpf_pinning_composite_key
{
    GUID namespace_guid;
    cxplat_utf8_string_t path;
} ebpf_pinning_composite_key_t;

/**
 * @brief Internal pinning table entry that uses composite keys
 * This differs from the public ebpf_pinning_entry_t structure
 */
typedef struct _ebpf_pinning_table_entry
{
    ebpf_pinning_composite_key_t key;
    ebpf_core_object_t* object;
} ebpf_pinning_table_entry_t;

/**
 * @brief Custom hash function for pinning table that incorporates namespace isolation.
 * Creates a composite hash of the namespace GUID and the path string from the composite key.
 */
static uint32_t
_ebpf_pinning_table_hash_function(_In_ const uint8_t* key, _In_ uint32_t seed)
{
    // Key is a pointer to ebpf_pinning_composite_key_t
    const ebpf_pinning_composite_key_t* composite_key = *(const ebpf_pinning_composite_key_t**)key;

    // Create array of data blobs to hash: namespace + path
    const uint8_t* data_blobs[] = {(const uint8_t*)&composite_key->namespace_guid, composite_key->path.value};

    const size_t data_lengths[] = {sizeof(GUID), composite_key->path.length};

    // Use the chain hash function to combine namespace and path
    return ebpf_hash_table_compute_chain_hash(seed, 2, data_blobs, data_lengths);
}

static int
_ebpf_pinning_table_compare(_In_ const uint8_t* key1, _In_ const uint8_t* key2);

static void
_ebpf_pinning_entry_free(_Frees_ptr_opt_ ebpf_pinning_table_entry_t* pinning_entry)
{
    if (!pinning_entry) {
        return;
    }
    EBPF_OBJECT_RELEASE_REFERENCE_USER(pinning_entry->object);
    ebpf_free(pinning_entry->key.path.value);
    ebpf_free(pinning_entry);
}

/**
 * @brief Helper function to delete a pinning entry by composite key
 * @param pinning_table The pinning table
 * @param composite_key The composite key to delete
 * @param log_path Optional path for logging (can be NULL to skip logging)
 * @return EBPF_SUCCESS if the entry was found and deleted, error code otherwise
 */
static ebpf_result_t
_ebpf_pinning_table_delete_by_composite_key(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    _In_ const ebpf_pinning_composite_key_t* composite_key,
    _In_opt_ const cxplat_utf8_string_t* log_path)
{
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    ebpf_pinning_table_entry_t** existing_pinning_entry;
    ebpf_pinning_table_entry_t* entry = NULL;

    state = ebpf_lock_lock(&pinning_table->lock);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&composite_key, (uint8_t**)&existing_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        entry = *existing_pinning_entry;
        return_value = ebpf_hash_table_delete(pinning_table->hash_table, (const uint8_t*)&composite_key);
        // If unable to remove the entry from the table, don't delete it.
        if (return_value != EBPF_SUCCESS) {
            entry = NULL;
        }
    }
    ebpf_lock_unlock(&pinning_table->lock, state);

    // Log the free of the path before freeing the entry (which may contain the path).
    if (return_value == EBPF_SUCCESS && log_path != NULL) {
        EBPF_LOG_MESSAGE_UTF8_STRING(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "Unpinned object", log_path);
    }

    if (entry != NULL) {
        ebpf_interlocked_decrement_int32(&entry->object->pinned_path_count);
        _ebpf_pinning_entry_free(entry);
    }

    return return_value;
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_allocate(ebpf_pinning_table_t** pinning_table)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    *pinning_table = ebpf_allocate_with_tag(sizeof(ebpf_pinning_table_t), EBPF_POOL_TAG_PINNING);
    if (*pinning_table == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(*pinning_table, 0, sizeof(ebpf_pinning_table_t));

    ebpf_lock_create(&(*pinning_table)->lock);

    const ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(ebpf_pinning_composite_key_t*),
        .value_size = sizeof(ebpf_pinning_table_entry_t*),
        .hash_function = _ebpf_pinning_table_hash_function,
        .compare_function = _ebpf_pinning_table_compare,
        .allocate = ebpf_allocate_with_tag,
        .allocation_tag = EBPF_POOL_TAG_PINNING,
        .free = ebpf_free,
    };

    return_value = ebpf_hash_table_create(&(*pinning_table)->hash_table, &options);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = EBPF_SUCCESS;
Done:
    if (return_value != EBPF_SUCCESS) {
        if ((*pinning_table)) {
            ebpf_hash_table_destroy((*pinning_table)->hash_table);
        }

        ebpf_free(*pinning_table);
        *pinning_table = NULL;
    }

    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_pinning_composite_key_t* key = NULL;
    if (pinning_table && pinning_table->hash_table) {
        for (;;) {
            return_value = ebpf_hash_table_next_key(pinning_table->hash_table, NULL, (uint8_t*)&key);
            if (return_value != EBPF_SUCCESS) {
                break;
            }
            // Delete this entry using the helper function (no logging needed during table destruction)
            _ebpf_pinning_table_delete_by_composite_key(pinning_table, key, NULL);
        }
        ebpf_hash_table_destroy(pinning_table->hash_table);
    }

    ebpf_free(pinning_table);
    pinning_table = NULL;
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_insert(
    ebpf_pinning_table_t* pinning_table, const cxplat_utf8_string_t* path, ebpf_core_object_t* object)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    ebpf_pinning_composite_key_t* new_key;
    ebpf_pinning_table_entry_t* new_pinning_entry;

    if (path->length >= EBPF_MAX_PIN_PATH_LENGTH || path->length == 0) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    // Block embedded null terminators
    for (size_t index = 0; index < path->length; index++) {
        if (path->value[index] == 0) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
    }

    new_pinning_entry = ebpf_allocate_with_tag(sizeof(ebpf_pinning_table_entry_t), EBPF_POOL_TAG_PINNING);
    if (!new_pinning_entry) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // Set up the composite key with current namespace and path
    new_pinning_entry->key.namespace_guid = ebpf_namespace_get_current();
    return_value = ebpf_duplicate_utf8_string(&new_pinning_entry->key.path, path);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    new_pinning_entry->object = object;
    EBPF_OBJECT_ACQUIRE_REFERENCE_USER(object);
    new_key = &new_pinning_entry->key;

    state = ebpf_lock_lock(&pinning_table->lock);

    return_value = ebpf_hash_table_update(
        pinning_table->hash_table,
        (const uint8_t*)&new_key,
        (const uint8_t*)&new_pinning_entry,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (return_value == EBPF_KEY_ALREADY_EXISTS) {
        return_value = EBPF_OBJECT_ALREADY_EXISTS;
    } else if (return_value == EBPF_SUCCESS) {
        new_pinning_entry = NULL;
        ebpf_interlocked_increment_int32(&object->pinned_path_count);
    }

    ebpf_lock_unlock(&pinning_table->lock, state);

Done:
    _ebpf_pinning_entry_free(new_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UTF8_STRING(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "Pinned object", path);
    }

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_find(
    ebpf_pinning_table_t* pinning_table, const cxplat_utf8_string_t* path, ebpf_core_object_t** object)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    ebpf_pinning_composite_key_t search_key;
    const ebpf_pinning_composite_key_t* existing_key = &search_key;
    ebpf_pinning_table_entry_t** existing_pinning_entry;

    // Create composite search key with current namespace and provided path
    search_key.namespace_guid = ebpf_namespace_get_current();
    search_key.path = *path; // Shallow copy is sufficient for search

    state = ebpf_lock_lock(&pinning_table->lock);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);

    if (return_value == EBPF_SUCCESS) {
        ebpf_core_object_t* found_object = (*existing_pinning_entry)->object;
        *object = found_object;
        EBPF_OBJECT_ACQUIRE_REFERENCE(*object);
    }

    ebpf_lock_unlock(&pinning_table->lock, state);

    EBPF_RETURN_FUNCTION_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const cxplat_utf8_string_t* path)
{
    EBPF_LOG_ENTRY();
    ebpf_pinning_composite_key_t search_key;

    // Create composite search key with current namespace and provided path
    search_key.namespace_guid = ebpf_namespace_get_current();
    search_key.path = *path; // Shallow copy is sufficient for search

    ebpf_result_t return_value = _ebpf_pinning_table_delete_by_composite_key(pinning_table, &search_key, path);

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_enumerate_entries(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    ebpf_object_type_t object_type,
    _Out_ uint16_t* entry_count,
    _Outptr_result_buffer_maybenull_(*entry_count) ebpf_pinning_entry_t** pinning_entries)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    bool lock_held = FALSE;
    uint16_t local_entry_count = 0;
    uint16_t entries_array_length = 0;
    ebpf_pinning_entry_t* local_pinning_entries = NULL;
    cxplat_utf8_string_t* next_object_path;
    ebpf_pinning_entry_t* new_entry = NULL;

    ebpf_assert(entry_count);
    ebpf_assert(pinning_entries);

    state = ebpf_lock_lock(&pinning_table->lock);
    lock_held = TRUE;

    // Get output array length by finding how many entries are there in the pinning table.
    entries_array_length = (uint16_t)ebpf_hash_table_key_count(pinning_table->hash_table);

    // Exit if there are no entries.
    if (entries_array_length == 0) {
        goto Exit;
    }

    // Allocate the output array for storing the pinning entries.
    local_pinning_entries = (ebpf_pinning_entry_t*)ebpf_allocate_with_tag(
        sizeof(ebpf_pinning_entry_t) * entries_array_length, EBPF_POOL_TAG_DEFAULT);
    if (local_pinning_entries == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Loop through the entries in the hashtable.
    next_object_path = NULL;
    for (;;) {
        ebpf_pinning_table_entry_t** next_pinning_entry = NULL;

        // Find next pinning entry, if any.
        result = ebpf_hash_table_next_key_and_value(
            pinning_table->hash_table,
            (const uint8_t*)((next_object_path == NULL) ? NULL : &next_object_path),
            (uint8_t*)&next_object_path,
            (uint8_t**)&next_pinning_entry);

        if (result == EBPF_NO_MORE_KEYS) {
            // Reached end of hashtable.
            result = EBPF_SUCCESS;
            break;
        }

        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Skip entries that don't match the input object type.
        if (object_type != ebpf_object_get_type((*next_pinning_entry)->object)) {
            continue;
        }

        // Skip entries that are not in the current namespace.
        GUID current_namespace = ebpf_namespace_get_current();
        if (!IsEqualGUID(&(*next_pinning_entry)->key.namespace_guid, &current_namespace)) {
            continue;
        }

        local_entry_count++;
        ebpf_assert(local_entry_count <= entries_array_length);

        // Copy the next pinning entry to a new entry in the output array.
        // Convert from internal entry to public entry (only path and object)
        new_entry = &local_pinning_entries[local_entry_count - 1];
        new_entry->object = (*next_pinning_entry)->object;

        // Take reference on underlying ebpf_object.
        EBPF_OBJECT_ACQUIRE_REFERENCE(new_entry->object);

        // Duplicate pinning object path (only the path, not the composite key).
        result = ebpf_duplicate_utf8_string(&new_entry->path, &(*next_pinning_entry)->key.path);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

Exit:
    // Release lock if held.
    if (lock_held) {
        ebpf_lock_unlock(&pinning_table->lock, state);
    }

    if (result != EBPF_SUCCESS) {
        ebpf_pinning_entries_release(local_entry_count, local_pinning_entries);
        local_entry_count = 0;
        local_pinning_entries = NULL;
    }

    // Set output parameters.
    *entry_count = local_entry_count;
    *pinning_entries = local_pinning_entries;

    EBPF_RETURN_RESULT(result);
}

static bool
_ebpf_pinning_table_match_object_type(_In_ void* filter_context, _In_ const uint8_t* key, _In_ const uint8_t* value)
{
    ebpf_object_type_t object_type = *(ebpf_object_type_t*)filter_context;
    ebpf_pinning_table_entry_t* entry = *(ebpf_pinning_table_entry_t**)value;
    UNREFERENCED_PARAMETER(key);

    if (object_type == EBPF_OBJECT_UNKNOWN) {
        return true;
    }

    return ebpf_object_get_type(entry->object) == object_type;
}

typedef struct _ebpf_pinning_table_match_context
{
    ebpf_object_type_t object_type;
    GUID namespace;
} ebpf_pinning_table_match_context_t;

static bool
_ebpf_pinning_table_match_object_type_and_namespace(
    _In_ void* filter_context, _In_ const uint8_t* key, _In_ const uint8_t* value)
{
    ebpf_pinning_table_match_context_t* context = (ebpf_pinning_table_match_context_t*)filter_context;
    ebpf_pinning_table_entry_t* entry = *(ebpf_pinning_table_entry_t**)value;
    const ebpf_pinning_composite_key_t* composite_key = *(const ebpf_pinning_composite_key_t**)key;

    // Check object type
    if (context->object_type != EBPF_OBJECT_UNKNOWN && ebpf_object_get_type(entry->object) != context->object_type) {
        return false;
    }

    // Check namespace using the composite key
    if (!IsEqualGUID(&composite_key->namespace_guid, &context->namespace)) {
        return false;
    }

    return true;
}

static int
_ebpf_pinning_table_compare(_In_ const uint8_t* key1, _In_ const uint8_t* key2)
{
    const ebpf_pinning_composite_key_t* composite_key1 = *(const ebpf_pinning_composite_key_t**)key1;
    const ebpf_pinning_composite_key_t* composite_key2 = *(const ebpf_pinning_composite_key_t**)key2;

    // First compare namespace GUIDs
    int namespace_result = memcmp(&composite_key1->namespace_guid, &composite_key2->namespace_guid, sizeof(GUID));
    if (namespace_result != 0) {
        return namespace_result;
    }

    // If namespaces are equal, compare paths
    const cxplat_utf8_string_t* path1 = &composite_key1->path;
    const cxplat_utf8_string_t* path2 = &composite_key2->path;

    size_t min_length = (path1->length < path2->length) ? path1->length : path2->length;
    int result = memcmp(path1->value, path2->value, min_length);

    if (result != 0) {
        return result;
    }

    if (path1->length < path2->length) {
        return -1;
    }

    if (path1->length > path2->length) {
        return 1;
    }

    return 0;
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_get_next_path(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    _Inout_ ebpf_object_type_t* object_type,
    _In_ const cxplat_utf8_string_t* start_path,
    _Inout_ cxplat_utf8_string_t* next_path)
{
    EBPF_LOG_ENTRY();
    if ((pinning_table == NULL) || (start_path == NULL) || (next_path == NULL) || (object_type == NULL)) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    // Create composite key for starting point if we have a start path
    ebpf_pinning_composite_key_t start_composite_key;
    const ebpf_pinning_composite_key_t* previous_composite_key = NULL;
    if (start_path->length > 0) {
        start_composite_key.namespace_guid = ebpf_namespace_get_current();
        start_composite_key.path = *start_path; // Shallow copy
        previous_composite_key = &start_composite_key;
    }

    const uint8_t* previous_key = (previous_composite_key == NULL) ? NULL : (const uint8_t*)&previous_composite_key;

    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);

    ebpf_result_t result;
    ebpf_pinning_table_entry_t** next_pinning_entry = NULL;

    // Get the next entry in the table.
    ebpf_pinning_composite_key_t** next_composite_key;
    ebpf_pinning_table_match_context_t context = {
        .object_type = *object_type, .namespace = ebpf_namespace_get_current()};
    result = ebpf_hash_table_next_key_and_value_sorted(
        pinning_table->hash_table,
        previous_key,
        _ebpf_pinning_table_compare,
        &context,
        _ebpf_pinning_table_match_object_type_and_namespace,
        (uint8_t*)&next_composite_key,
        (uint8_t**)&next_pinning_entry);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (next_path->length < (*next_pinning_entry)->key.path.length) {
        result = EBPF_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    next_path->length = (*next_pinning_entry)->key.path.length;
    memcpy(next_path->value, (*next_pinning_entry)->key.path.value, next_path->length);
    *object_type = ebpf_object_get_type((*next_pinning_entry)->object);
    result = EBPF_SUCCESS;

Exit:
    ebpf_lock_unlock(&pinning_table->lock, state);
    EBPF_RETURN_RESULT(result);
}

void
ebpf_pinning_entries_release(uint16_t entry_count, _In_opt_count_(entry_count) ebpf_pinning_entry_t* pinning_entries)
{
    EBPF_LOG_ENTRY();
    uint16_t index;
    if (!pinning_entries) {
        EBPF_RETURN_VOID();
    }

    for (index = 0; index < entry_count; index++) {
        ebpf_pinning_entry_t* entry = &pinning_entries[index];
        ebpf_free(entry->path.value);
        entry->path.value = NULL;
        EBPF_OBJECT_RELEASE_REFERENCE(entry->object);
    }
    ebpf_free(pinning_entries);
    EBPF_RETURN_VOID();
}
