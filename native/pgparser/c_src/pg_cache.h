/*
 * pg_cache.h — per-scheduler ShapeKey -> ParseInfo LRU cache.
 *
 * Each instance is only ever accessed by a single scheduler thread (via
 * enif_tsd), hence no locks. Stats counters are plain fields; aggregated
 * reads tolerate races (monitoring metrics allow approximate values).
 */
#ifndef PG_CACHE_H
#define PG_CACHE_H

#include <stdbool.h>
#include <stdint.h>

#include "pg_parse_info.h"
#include "pg_shape.h"

typedef struct pg_cache_entry
{
    pg_shape_key_t key;
    pg_parse_info_t *info;              /* owned by the cache */
    struct pg_cache_entry *hnext;       /* hash bucket chain */
    struct pg_cache_entry *prev, *next; /* LRU doubly-linked list, head = MRU */
} pg_cache_entry_t;

typedef struct pg_cache_stats
{
    uint64_t hits;
    uint64_t misses;
    uint64_t bypass_allowlist;
    uint64_t bypass_multi_statement;
    uint64_t bypass_scan_error;
    uint64_t bypass_unsafe_literal;
    uint64_t inserts;
    uint64_t evictions;
    uint64_t parses;       /* raw parse executions (miss + bypass + disabled) */
    uint64_t parse_errors; /* failed parses */
} pg_cache_stats_t;

typedef struct pg_cache
{
    uint32_t max_entries;
    uint32_t entry_count;
    uint32_t bucket_count; /* power of two */
    pg_cache_entry_t **buckets;
    pg_cache_entry_t *lru_head;
    pg_cache_entry_t *lru_tail;
    struct pg_cache *registry_next; /* NIF-side global registry chain */
    pg_cache_stats_t stats;
} pg_cache_t;

pg_cache_t *pg_cache_create(uint32_t max_entries);
void pg_cache_destroy(pg_cache_t *cache);

/*
 * Hit: promote the entry to the LRU head and return the cache-owned info
 * (caller reads only, does not take ownership). Miss returns NULL.
 * hits/misses counters are updated internally.
 */
const pg_parse_info_t *pg_cache_lookup(pg_cache_t *cache,
                                       const pg_shape_key_t *key);

/*
 * Insert and take ownership of info; replaces an existing entry with the
 * same key; evicts the LRU tail when over capacity. Returns false on
 * allocation failure (nothing cached, info ownership stays with the
 * caller).
 */
bool pg_cache_insert(pg_cache_t *cache, const pg_shape_key_t *key,
                     pg_parse_info_t *info);

#endif /* PG_CACHE_H */
