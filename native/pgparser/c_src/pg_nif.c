/*
 * pg_nif.c — C NIF boundary of Supavisor.PgParser.
 *
 * Stable upward contract (the shape of statement_types/1's return value is
 * preserved verbatim):
 *   {:ok, ["SelectStmt", ...]} | {:error, "Error parsing query"}
 *
 * Cache model: per-scheduler (enif_tsd_get/set); each thread owns a
 * lock-free LRU cache. The hit path only runs the PostgreSQL scanner to
 * build the ShapeKey — no parse, no AST. On a miss, one raw parse runs and
 * the entry is inserted only after AST validation (single statement +
 * allowlist family). Bypasses (outside the allowlist / multi-statement /
 * scanner error) still go through a full parse and behave exactly as if
 * the cache were disabled.
 *
 * Hot upgrade: the upgrade callback reuses the old priv_data only when it
 * carries our magic and the same PG_NIF_STATE_ABI_VERSION (TSD key, caches
 * and the secret then survive); otherwise it performs a fresh load and
 * leaves the old state to the old library's own unload. When
 * PG_PARSE_INFO_RULES_VERSION changes, old keys expire naturally because
 * their context header differs.
 */
#include <erl_nif.h>

#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#include <postgres.h> /* prerequisite for the NodeTag constants (T_SelectStmt etc.) */
#include <nodes/nodes.h>

#include "pg_cache.h"
#include "pg_parse_info.h"
#include "pg_shape.h"

/* Native-state identity for hot upgrade. magic must stay at offset 0 and
 * abi_version right after it, forever: nif_upgrade reads them from a priv
 * that may have been allocated by a different library (e.g. the former
 * Rustler one) to decide whether the old state may be reused. Bump
 * PG_NIF_STATE_ABI_VERSION whenever ANY reused layout or signature changes
 * (pg_nif_priv_t, pg_cache_t, pg_cache_entry_t, pg_shape_key_t,
 * pg_parse_info_t, the pg_cache_* functions). */
#define PG_NIF_STATE_MAGIC 0x5047504152534501ULL /* "PGPARSE\1" */
#define PG_NIF_STATE_ABI_VERSION 2u /* 2: pg_shape_key_t digest 32B -> 8B (XXH64) */

typedef struct pg_nif_priv
{
    uint64_t magic;       /* PG_NIF_STATE_MAGIC; must remain the first field */
    uint32_t abi_version; /* PG_NIF_STATE_ABI_VERSION */
    ErlNifTSDKey tsd_key;
    ErlNifMutex *registry_mutex;
    pg_cache_t *registry; /* list of all per-scheduler caches (stats aggregation) */
    uint32_t registry_count;
    uint32_t cache_size;  /* max entries per scheduler, 0 = cache disabled */
    uint8_t secret[PG_HASH_KEY_LEN];
} pg_nif_priv_t;

/* ---------------------------------------------------------------- helpers */

static ERL_NIF_TERM
make_binary(ErlNifEnv *env, const char *str)
{
    size_t len = strlen(str);
    ERL_NIF_TERM term;
    unsigned char *buf = enif_make_new_binary(env, len, &term);

    memcpy(buf, str, len);
    return term;
}

static ERL_NIF_TERM
error_term(ErlNifEnv *env)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            make_binary(env, "Error parsing query"));
}

static bool
kind_allowlisted(uint32_t tag)
{
    return tag == T_SelectStmt || tag == T_InsertStmt ||
           tag == T_UpdateStmt || tag == T_DeleteStmt || tag == T_MergeStmt;
}

static ERL_NIF_TERM
info_to_term(ErlNifEnv *env, const pg_parse_info_t *info)
{
    ERL_NIF_TERM list = enif_make_list(env, 0);
    uint32_t i;

    for (i = info->statement_count; i > 0; i--)
    {
        const char *name = pg_nodetag_name(info->stmt_kinds[i - 1]);

        /* the generated table covers every NodeTag; NULL only appears when
           the generated table is out of date */
        if (name == NULL)
            name = "Invalid";
        list = enif_make_list_cell(env, make_binary(env, name), list);
    }
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), list);
}

static void
random_secret(uint8_t out[PG_HASH_KEY_LEN])
{
#if defined(__linux__)
    if (getrandom(out, PG_HASH_KEY_LEN, 0) == PG_HASH_KEY_LEN)
        return;
#elif defined(__APPLE__)
    arc4random_buf(out, PG_HASH_KEY_LEN);
    return;
#endif
    {
        FILE *f = fopen("/dev/urandom", "rb");

        if (f != NULL)
        {
            size_t n = fread(out, 1, PG_HASH_KEY_LEN, f);

            (void) n;
            fclose(f);
        }
    }
}

/* Return the current thread's (scheduler's) cache, creating and
 * registering it on first use */
static pg_cache_t *
get_cache(pg_nif_priv_t *priv)
{
    pg_cache_t *cache = enif_tsd_get(priv->tsd_key);

    if (cache == NULL)
    {
        cache = pg_cache_create(priv->cache_size);
        if (cache == NULL)
            return NULL;
        enif_tsd_set(priv->tsd_key, cache);

        enif_mutex_lock(priv->registry_mutex);
        cache->registry_next = priv->registry;
        priv->registry = cache;
        priv->registry_count++;
        enif_mutex_unlock(priv->registry_mutex);
    }
    return cache;
}

/* ------------------------------------------------------------------ NIFs */

static ERL_NIF_TERM
nif_statement_types(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary sql;
    pg_nif_priv_t *priv;
    pg_cache_t *cache = NULL;
    pg_shape_key_t key;
    pg_shape_eligibility_t elig = PG_SHAPE_BYPASS_SCAN_ERROR;
    const pg_parse_info_t *hit = NULL;
    pg_parse_info_t *built = NULL;
    ERL_NIF_TERM term;
    char *query;
    bool ok;

    if (argc != 1 || !enif_inspect_binary(env, argv[0], &sql))
        return enif_make_badarg(env);

    priv = enif_priv_data(env);

    /* libpg_query requires NUL-terminated input; anything past an embedded
       NUL is invisible to the parser, matching pg_query.rs's CString
       behavior (the caller already trims trailing NULs). */
    query = enif_alloc(sql.size + 1);
    if (query == NULL)
        return error_term(env);
    memcpy(query, sql.data, sql.size);
    query[sql.size] = '\0';

    if (priv->cache_size > 0 && (cache = get_cache(priv)) != NULL)
    {
        elig = pg_shape_scan(query, priv->secret, &key);
        switch (elig)
        {
        case PG_SHAPE_ELIGIBLE:
            hit = pg_cache_lookup(cache, &key);
            break;
        case PG_SHAPE_BYPASS_ALLOWLIST:
            cache->stats.bypass_allowlist++;
            break;
        case PG_SHAPE_BYPASS_MULTI_STATEMENT:
            cache->stats.bypass_multi_statement++;
            break;
        case PG_SHAPE_BYPASS_SCAN_ERROR:
            cache->stats.bypass_scan_error++;
            break;
        case PG_SHAPE_BYPASS_UNSAFE_LITERAL:
            cache->stats.bypass_unsafe_literal++;
            break;
        }
    }

    if (hit != NULL)
    {
        enif_free(query);
        return info_to_term(env, hit);
    }

    /* miss / bypass / cache disabled: full parse (same error semantics as
       the no-cache path) */
    if (cache != NULL)
        cache->stats.parses++;
    ok = pg_parse_info_build(query, &built);
    enif_free(query);
    if (!ok)
    {
        if (cache != NULL)
            cache->stats.parse_errors++;
        return error_term(env);
    }

    /* AST validation: only a single statement whose kind belongs to the
       allowlist family may enter the cache */
    {
        const pg_parse_info_t *result = built;

        if (elig == PG_SHAPE_ELIGIBLE && cache != NULL &&
            built->statement_count == 1 && kind_allowlisted(built->stmt_kinds[0]))
        {
            if (pg_cache_insert(cache, &key, built))
                built = NULL; /* ownership transferred to the cache; the memory
                                 behind result stays valid */
        }

        term = info_to_term(env, result);
        if (built != NULL)
            pg_parse_info_free(built);
    }
    return term;
}

static ERL_NIF_TERM
nif_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    pg_nif_priv_t *priv;
    pg_cache_t *cache;
    pg_cache_stats_t sum = {0};
    uint64_t entries = 0;
    uint32_t schedulers;
    ERL_NIF_TERM map;

    if (argc != 0)
        return enif_make_badarg(env);

    priv = enif_priv_data(env);

    /* the mutex only protects the registry structure; counter reads are
       racy on purpose (monitoring metrics tolerate approximate values) */
    enif_mutex_lock(priv->registry_mutex);
    for (cache = priv->registry; cache != NULL; cache = cache->registry_next)
    {
        sum.hits += cache->stats.hits;
        sum.misses += cache->stats.misses;
        sum.bypass_allowlist += cache->stats.bypass_allowlist;
        sum.bypass_multi_statement += cache->stats.bypass_multi_statement;
        sum.bypass_scan_error += cache->stats.bypass_scan_error;
        sum.bypass_unsafe_literal += cache->stats.bypass_unsafe_literal;
        sum.inserts += cache->stats.inserts;
        sum.evictions += cache->stats.evictions;
        sum.parses += cache->stats.parses;
        sum.parse_errors += cache->stats.parse_errors;
        entries += cache->entry_count;
    }
    schedulers = priv->registry_count;
    enif_mutex_unlock(priv->registry_mutex);

    map = enif_make_new_map(env);
#define PUT_UINT(key_name, value)                                              \
    enif_make_map_put(env, map, enif_make_atom(env, key_name),                 \
                      enif_make_uint64(env, (ErlNifUInt64) (value)), &map)
    PUT_UINT("hits", sum.hits);
    PUT_UINT("misses", sum.misses);
    PUT_UINT("bypasses",
             sum.bypass_allowlist + sum.bypass_multi_statement +
                 sum.bypass_scan_error + sum.bypass_unsafe_literal);
    PUT_UINT("bypass_allowlist", sum.bypass_allowlist);
    PUT_UINT("bypass_multi_statement", sum.bypass_multi_statement);
    PUT_UINT("bypass_scan_error", sum.bypass_scan_error);
    PUT_UINT("bypass_unsafe_literal", sum.bypass_unsafe_literal);
    PUT_UINT("inserts", sum.inserts);
    PUT_UINT("evictions", sum.evictions);
    PUT_UINT("entries", entries);
    PUT_UINT("parses", sum.parses);
    PUT_UINT("parse_errors", sum.parse_errors);
    PUT_UINT("schedulers", schedulers);
    PUT_UINT("max_entries", priv->cache_size);
#undef PUT_UINT
    return map;
}

/* ------------------------------------------------------------- lifecycle */

static int
nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    pg_nif_priv_t *priv;
    unsigned int cache_size;

    priv = enif_alloc(sizeof(pg_nif_priv_t));
    if (priv == NULL)
        return 1;

    if (!enif_get_uint(env, load_info, &cache_size))
    {
        enif_free(priv);
        return 1;
    }

    if (enif_tsd_key_create("pgparser_cache", &priv->tsd_key) != 0)
    {
        enif_free(priv);
        return 1;
    }
    priv->registry_mutex = enif_mutex_create("pgparser_registry");
    if (priv->registry_mutex == NULL)
    {
        enif_tsd_key_destroy(priv->tsd_key);
        enif_free(priv);
        return 1;
    }
    priv->magic = PG_NIF_STATE_MAGIC;
    priv->abi_version = PG_NIF_STATE_ABI_VERSION;
    priv->registry = NULL;
    priv->registry_count = 0;
    priv->cache_size = cache_size;
    random_secret(priv->secret);

    *priv_data = priv;
    return 0;
}

static int
nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data,
            ERL_NIF_TERM load_info)
{
    /* Reuse the old instance only when it is provably ours and layout-
       compatible: TSD key / caches / secret then survive, and the old
       library's unload receives NULL. A foreign priv (e.g. the former
       Rustler library's) or a different ABI version fails the check: fall
       back to a fresh load and leave *old_priv_data untouched, so the old
       library's own unload frees its state using its own layout. The
       caches are volatile by design, so dropping them across an ABI break
       needs no migration. Reading the magic at offset 0 of a foreign priv
       is safe in practice: real allocators round even small allocations
       well past 8 bytes. */
    pg_nif_priv_t *priv = *old_priv_data;
    unsigned int cache_size;

    if (priv == NULL)
        return nif_load(env, priv_data, load_info);

    if (priv->magic != PG_NIF_STATE_MAGIC ||
        priv->abi_version != PG_NIF_STATE_ABI_VERSION)
        return nif_load(env, priv_data, load_info);

    if (enif_get_uint(env, load_info, &cache_size))
        priv->cache_size = cache_size; /* the new bound applies to caches
                                          created afterwards */

    *priv_data = priv;
    *old_priv_data = NULL;
    return 0;
}

static void
nif_unload(ErlNifEnv *env, void *priv_data)
{
    pg_nif_priv_t *priv = priv_data;
    pg_cache_t *cache;
    pg_cache_t *next;

    (void) env;
    if (priv == NULL)
        return;

    enif_mutex_lock(priv->registry_mutex);
    for (cache = priv->registry; cache != NULL; cache = next)
    {
        next = cache->registry_next;
        pg_cache_destroy(cache);
    }
    priv->registry = NULL;
    enif_mutex_unlock(priv->registry_mutex);

    enif_mutex_destroy(priv->registry_mutex);
    enif_tsd_key_destroy(priv->tsd_key);
    enif_free(priv);
}

static ErlNifFunc nif_funcs[] = {
    {"statement_types", 1, nif_statement_types, 0},
    {"cache_stats", 0, nif_cache_stats, 0}
};

ERL_NIF_INIT(Elixir.Supavisor.PgParser, nif_funcs, nif_load, NULL,
             nif_upgrade, nif_unload)
