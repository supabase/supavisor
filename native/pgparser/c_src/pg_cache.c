#include "pg_cache.h"

#include <stdlib.h>
#include <string.h>

static uint32_t
next_pow2(uint32_t n)
{
    uint32_t p = 16;

    while (p < n)
        p <<= 1;
    return p;
}

static uint32_t
key_bucket(const pg_cache_t *cache, const pg_shape_key_t *key)
{
    uint64_t h;

    memcpy(&h, key->digest, sizeof(h)); /* hash = the whole 64-bit digest */
    return (uint32_t) (h & (uint64_t) (cache->bucket_count - 1));
}

static bool
key_equal(const pg_shape_key_t *a, const pg_shape_key_t *b)
{
    return a->token_count == b->token_count &&
           a->serialized_size == b->serialized_size &&
           memcmp(a->digest, b->digest, PG_SHAPE_DIGEST_LEN) == 0;
}

static void
lru_remove(pg_cache_t *cache, pg_cache_entry_t *entry)
{
    if (entry->prev != NULL)
        entry->prev->next = entry->next;
    else
        cache->lru_head = entry->next;
    if (entry->next != NULL)
        entry->next->prev = entry->prev;
    else
        cache->lru_tail = entry->prev;
    entry->prev = entry->next = NULL;
}

static void
lru_push_head(pg_cache_t *cache, pg_cache_entry_t *entry)
{
    entry->prev = NULL;
    entry->next = cache->lru_head;
    if (cache->lru_head != NULL)
        cache->lru_head->prev = entry;
    cache->lru_head = entry;
    if (cache->lru_tail == NULL)
        cache->lru_tail = entry;
}

static pg_cache_entry_t *
find_entry(pg_cache_t *cache, const pg_shape_key_t *key, uint32_t bucket)
{
    pg_cache_entry_t *entry;

    for (entry = cache->buckets[bucket]; entry != NULL; entry = entry->hnext)
    {
        if (key_equal(&entry->key, key))
            return entry;
    }
    return NULL;
}

static void
free_entry(pg_cache_entry_t *entry)
{
    pg_parse_info_free(entry->info);
    free(entry);
}

/* Unlink the entry from its hash bucket and the LRU list, then free it
 * (does not update counters) */
static void
drop_entry(pg_cache_t *cache, pg_cache_entry_t *entry, uint32_t bucket)
{
    pg_cache_entry_t **pp = &cache->buckets[bucket];

    while (*pp != NULL && *pp != entry)
        pp = &(*pp)->hnext;
    if (*pp != NULL)
        *pp = entry->hnext;
    lru_remove(cache, entry);
    free_entry(entry);
    cache->entry_count--;
}

static void
evict_tail(pg_cache_t *cache)
{
    pg_cache_entry_t *tail = cache->lru_tail;

    if (tail == NULL)
        return;
    drop_entry(cache, tail, key_bucket(cache, &tail->key));
    cache->stats.evictions++;
}

pg_cache_t *
pg_cache_create(uint32_t max_entries)
{
    pg_cache_t *cache;

    cache = calloc(1, sizeof(pg_cache_t));
    if (cache == NULL)
        return NULL;
    cache->max_entries = max_entries;
    cache->bucket_count = next_pow2(max_entries * 2);
    cache->buckets = calloc(cache->bucket_count, sizeof(pg_cache_entry_t *));
    if (cache->buckets == NULL)
    {
        free(cache);
        return NULL;
    }
    return cache;
}

void
pg_cache_destroy(pg_cache_t *cache)
{
    pg_cache_entry_t *entry;
    pg_cache_entry_t *next;

    if (cache == NULL)
        return;
    for (entry = cache->lru_head; entry != NULL; entry = next)
    {
        next = entry->next;
        free_entry(entry);
    }
    free(cache->buckets);
    free(cache);
}

const pg_parse_info_t *
pg_cache_lookup(pg_cache_t *cache, const pg_shape_key_t *key)
{
    pg_cache_entry_t *entry;

    if (cache == NULL || cache->max_entries == 0)
        return NULL;

    entry = find_entry(cache, key, key_bucket(cache, key));
    if (entry == NULL)
    {
        cache->stats.misses++;
        return NULL;
    }

    cache->stats.hits++;
    lru_remove(cache, entry);
    lru_push_head(cache, entry);
    return entry->info;
}

bool
pg_cache_insert(pg_cache_t *cache, const pg_shape_key_t *key,
                pg_parse_info_t *info)
{
    uint32_t bucket;
    pg_cache_entry_t *entry;

    if (cache == NULL || cache->max_entries == 0 || info == NULL)
        return false;

    bucket = key_bucket(cache, key);

    /* same key already present: replace (callers should look up first;
       this is only a fallback) */
    entry = find_entry(cache, key, bucket);
    if (entry != NULL)
    {
        pg_parse_info_free(entry->info);
        entry->info = info;
        lru_remove(cache, entry);
        lru_push_head(cache, entry);
        cache->stats.inserts++;
        return true;
    }

    entry = malloc(sizeof(pg_cache_entry_t));
    if (entry == NULL)
        return false;
    entry->key = *key;
    entry->info = info;

    while (cache->entry_count >= cache->max_entries)
        evict_tail(cache);

    entry->hnext = cache->buckets[bucket];
    cache->buckets[bucket] = entry;
    lru_push_head(cache, entry);
    cache->entry_count++;
    cache->stats.inserts++;
    return true;
}
