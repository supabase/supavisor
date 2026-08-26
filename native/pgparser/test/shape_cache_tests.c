/*
 * shape_cache_tests — C unit tests for pg_hash_sink / pg_shape / pg_cache.
 *
 * Run: make -C native/pgparser test
 * The shape tests use a fixed all-zero key (the runtime uses random per-boot
 * seed material); an all-zero key folds to XXH64 seed 0, matching upstream's
 * published sanity vectors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pg_cache.h"
#include "pg_hash_sink.h"
#include "pg_parse_info.h"
#include "pg_shape.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                          \
    do                                                                       \
    {                                                                        \
        checks++;                                                            \
        if (!(cond))                                                         \
        {                                                                    \
            failures++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
        }                                                                    \
    } while (0)

static const uint8_t TEST_KEY[PG_HASH_KEY_LEN] = {0};

/* ------------------------------------------------------------- hash sink */

static void
test_hash_sink(void)
{
    pg_hash_sink_t a, b, c;
    uint8_t da[PG_SHAPE_DIGEST_LEN], db[PG_SHAPE_DIGEST_LEN],
        dc[PG_SHAPE_DIGEST_LEN];

    pg_hash_sink_init(&a, TEST_KEY);
    pg_hash_sink_write_u8(&a, 1);
    pg_hash_sink_write_u32be(&a, 0x01020304);
    pg_hash_sink_write_bytes(&a, "hello", 5);
    pg_hash_sink_finalize(&a, da);

    /* identical write sequences (including bulk writes crossing the internal
       32-byte buffer boundary) -> identical digest */
    pg_hash_sink_init(&b, TEST_KEY);
    pg_hash_sink_write_u8(&b, 1);
    pg_hash_sink_write_u32be(&b, 0x01020304);
    pg_hash_sink_write_bytes(&b, "hello", 5);
    pg_hash_sink_finalize(&b, db);
    CHECK(memcmp(da, db, PG_SHAPE_DIGEST_LEN) == 0);

    /* different content -> different digest */
    pg_hash_sink_init(&c, TEST_KEY);
    pg_hash_sink_write_u8(&c, 1);
    pg_hash_sink_write_u32be(&c, 0x01020305);
    pg_hash_sink_write_bytes(&c, "hello", 5);
    pg_hash_sink_finalize(&c, dc);
    CHECK(memcmp(da, dc, PG_SHAPE_DIGEST_LEN) != 0);

    /* large writes crossing the internal buffer boundary stay deterministic */
    {
        char buf[5000];
        uint8_t d1[PG_SHAPE_DIGEST_LEN], d2[PG_SHAPE_DIGEST_LEN];

        memset(buf, 'x', sizeof(buf));
        pg_hash_sink_init(&a, TEST_KEY);
        pg_hash_sink_write_bytes(&a, buf, sizeof(buf));
        pg_hash_sink_finalize(&a, d1);
        pg_hash_sink_init(&b, TEST_KEY);
        pg_hash_sink_write_bytes(&b, buf, sizeof(buf));
        pg_hash_sink_finalize(&b, d2);
        CHECK(memcmp(d1, d2, PG_SHAPE_DIGEST_LEN) == 0);
        CHECK(a.serialized_size == sizeof(buf));
    }
}

/* ------------------------------------- XXH64 known-answer tests (upstream) */

/* Pseudo-random sample buffer generator, copied (constants and algorithm)
   from upstream tests/sanity_test.c: the official vectors in
   tests/sanity_test_vectors.h hash the first len bytes of this buffer. */
#define KAT_PRIME32 2654435761U
#define KAT_PRIME64 11400714785074694797ULL

static void
kat_fill(uint8_t *buffer, size_t len)
{
    uint64_t byteGen = KAT_PRIME32;
    size_t i;

    for (i = 0; i < len; i++)
    {
        buffer[i] = (uint8_t) (byteGen >> 56);
        byteGen *= KAT_PRIME64;
    }
}

static void
test_xxh64_kat(void)
{
    /* Official XXH64 sanity vectors, xxHash v0.8.3
       tests/sanity_test_vectors.h (XSUM_XXH64_testdata rows) */
    static const struct
    {
        uint32_t len;
        uint64_t seed;
        uint64_t expect;
    } vectors[] = {
        {0, 0x0000000000000000ULL, 0xEF46DB3751D8E999ULL},
        {1, 0x0000000000000000ULL, 0xE934A84ADB052768ULL},
        {4, 0x0000000000000000ULL, 0x9136A0DCA57457EEULL},
        {8, 0x0000000000000000ULL, 0xCDBCF538E71D1348ULL},
        {14, 0x0000000000000000ULL, 0x8282DCC4994E35C8ULL},
        {100, 0x0000000000000000ULL, 0x4BFE019CD91D9EA4ULL},
        {1000, 0x0000000000000000ULL, 0x52BD1358F22E9EF7ULL},
        {2223, 0x0000000000000000ULL, 0xFF497304FD166727ULL},
        {2223, 0x000000009E3779B1ULL, 0xAC73280C18A80AEFULL},
    };
    uint8_t buf[2223];
    size_t i;

    kat_fill(buf, sizeof(buf));

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
    {
        /* one-shot against the extracted header */
        CHECK(XXH64(buf, vectors[i].len, vectors[i].seed) ==
              vectors[i].expect);

        /* streaming through pg_hash_sink: key material that folds to the
           vector's seed, then compare the canonical digest bytes */
        {
            uint8_t key[PG_HASH_KEY_LEN] = {0};
            pg_hash_sink_t sink;
            uint8_t digest[PG_SHAPE_DIGEST_LEN];
            XXH64_canonical_t canon;

            memcpy(key, &vectors[i].seed, 8); /* the other 24 bytes stay 0;
                                                 the fold reproduces seed */
            pg_hash_sink_init(&sink, key);
            pg_hash_sink_write_bytes(&sink, buf, vectors[i].len);
            pg_hash_sink_finalize(&sink, digest);
            XXH64_canonicalFromHash(&canon, vectors[i].expect);
            CHECK(memcmp(digest, canon.digest, PG_SHAPE_DIGEST_LEN) == 0);
        }
    }
}

static void
test_xxh64_streaming_consistency(void)
{
    /* The same byte stream fed in one bulk write, in 1-byte drips and in
       irregular chunks must produce the same digest (pins the internal
       32-byte buffer boundary handling) */
    uint8_t buf[1000];
    pg_hash_sink_t a, b, c;
    uint8_t da[PG_SHAPE_DIGEST_LEN], db[PG_SHAPE_DIGEST_LEN],
        dc[PG_SHAPE_DIGEST_LEN];
    size_t i, pos;
    static const size_t chunks[] = {1, 7, 31, 32, 33, 63, 64, 65, 128, 3};
    size_t ci = 0;

    kat_fill(buf, sizeof(buf));

    pg_hash_sink_init(&a, TEST_KEY);
    pg_hash_sink_write_bytes(&a, buf, sizeof(buf));
    pg_hash_sink_finalize(&a, da);

    pg_hash_sink_init(&b, TEST_KEY);
    for (i = 0; i < sizeof(buf); i++)
        pg_hash_sink_write_u8(&b, buf[i]);
    pg_hash_sink_finalize(&b, db);
    CHECK(memcmp(da, db, PG_SHAPE_DIGEST_LEN) == 0);
    CHECK(a.serialized_size == b.serialized_size);

    pg_hash_sink_init(&c, TEST_KEY);
    pos = 0;
    while (pos < sizeof(buf))
    {
        size_t n = chunks[ci];

        if (n > sizeof(buf) - pos)
            n = sizeof(buf) - pos;
        pg_hash_sink_write_bytes(&c, buf + pos, n);
        pos += n;
        ci = (ci + 1) % (sizeof(chunks) / sizeof(chunks[0]));
    }
    pg_hash_sink_finalize(&c, dc);
    CHECK(memcmp(da, dc, PG_SHAPE_DIGEST_LEN) == 0);
}

/* ----------------------------------------------------------------- shape */

static bool
scan(const char *sql, pg_shape_key_t *out)
{
    return pg_shape_scan(sql, TEST_KEY, out) == PG_SHAPE_ELIGIBLE;
}

static bool
key_eq(const pg_shape_key_t *a, const pg_shape_key_t *b)
{
    return a->token_count == b->token_count &&
           a->serialized_size == b->serialized_size &&
           memcmp(a->digest, b->digest, PG_SHAPE_DIGEST_LEN) == 0;
}

static void
test_shape_equivalence(void)
{
    pg_shape_key_t base, other;

    CHECK(scan("SELECT * FROM t WHERE id = 1", &base));

    /* constant value change (same type) -> same key */
    CHECK(scan("SELECT * FROM t WHERE id = 2", &other));
    CHECK(key_eq(&base, &other));

    /* whitespace / plain comments -> same key */
    CHECK(scan("  SELECT  *  FROM   t\nWHERE id = 1 -- comment\n", &other));
    CHECK(key_eq(&base, &other));
    CHECK(scan("SELECT /* inline */ * FROM t WHERE id = 1", &other));
    CHECK(key_eq(&base, &other));

    /* keyword case -> same key */
    CHECK(scan("select * from t where id = 1", &other));
    CHECK(key_eq(&base, &other));

    /* one or more trailing semicolons -> same key */
    CHECK(scan("SELECT * FROM t WHERE id = 1;", &other));
    CHECK(key_eq(&base, &other));
    CHECK(scan("SELECT * FROM t WHERE id = 1;;", &other));
    CHECK(key_eq(&base, &other));

    /* literal type change (int -> string) -> different key */
    CHECK(scan("SELECT * FROM t WHERE id = 'a'", &other));
    CHECK(!key_eq(&base, &other));

    /* the parameter number joins the key */
    CHECK(scan("SELECT * FROM t WHERE id = $1", &other));
    CHECK(!key_eq(&base, &other));

    /* quoted identifiers are case-sensitive */
    CHECK(scan("SELECT * FROM t WHERE \"ID\" = 1", &other));
    CHECK(!key_eq(&base, &other));

    /* quoted vs unquoted same-name identifier (identical after scanner
       normalization) -> same key */
    CHECK(scan("SELECT * FROM t WHERE \"id\" = 1", &other));
    CHECK(key_eq(&base, &other));

    /* comment markers and semicolons inside a string do not affect scanner
       state */
    CHECK(scan("SELECT * FROM t WHERE id = 1 AND note = '-- ; /* */'", &other));
    CHECK(!key_eq(&base, &other)); /* the extra AND condition changes the key */
    {
        pg_shape_key_t with_note, with_note2;

        CHECK(scan("SELECT * FROM t WHERE id = 1 AND note = '-- ; /* */'",
                   &with_note));
        CHECK(scan("SELECT * FROM t WHERE id = 1 AND note = '其他内容'",
                   &with_note2));
        CHECK(key_eq(&with_note, &with_note2)); /* both are string literals */
    }
}

static void
test_shape_eligibility(void)
{
    pg_shape_key_t k;

    /* the whole allowlist family is eligible */
    CHECK(pg_shape_scan("SELECT 1", TEST_KEY, &k) == PG_SHAPE_ELIGIBLE);
    CHECK(pg_shape_scan("INSERT INTO t VALUES (1)", TEST_KEY, &k) ==
          PG_SHAPE_ELIGIBLE);
    CHECK(pg_shape_scan("UPDATE t SET a = 1", TEST_KEY, &k) ==
          PG_SHAPE_ELIGIBLE);
    CHECK(pg_shape_scan("DELETE FROM t", TEST_KEY, &k) == PG_SHAPE_ELIGIBLE);
    CHECK(pg_shape_scan(
              "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
              TEST_KEY, &k) == PG_SHAPE_ELIGIBLE);

    /* anything outside the allowlist bypasses */
    CHECK(pg_shape_scan("PREPARE x AS SELECT 1", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("EXECUTE x(1)", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("DEALLOCATE x", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("BEGIN", TEST_KEY, &k) == PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("COMMIT", TEST_KEY, &k) == PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("SET search_path = public", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("EXPLAIN SELECT 1", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("WITH x AS (SELECT 1) SELECT * FROM x", TEST_KEY,
                        &k) == PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("DO $$ BEGIN END $$", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("COPY t FROM STDIN", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);

    /* multi-statement -> bypass (including content after a trailing
       semicolon, and a leading semicolon) */
    CHECK(pg_shape_scan("SELECT 1; SELECT 2", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_MULTI_STATEMENT);
    CHECK(pg_shape_scan("SELECT 1;; SELECT 2", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_MULTI_STATEMENT);
    CHECK(pg_shape_scan("; SELECT 1", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_MULTI_STATEMENT);
    CHECK(pg_shape_scan("SELECT 1; PREPARE x AS SELECT 2", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_MULTI_STATEMENT);

    /* scanner error -> bypass */
    CHECK(pg_shape_scan("SELECT 'unterminated", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_SCAN_ERROR);

    /* unicode literals bypass: their bodies and any UESCAPE clause are
       validated by the parser's token-filter layer (str_udeescape /
       check_uescapechar), not by the core scanner, so a folded shape
       could flip a parse from success to error */
    CHECK(pg_shape_scan("SELECT U&'abc'", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);
    CHECK(pg_shape_scan("SELECT U&'abc' UESCAPE '!'", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);
    CHECK(pg_shape_scan("SELECT * FROM t WHERE id = U&'\\0041'", TEST_KEY,
                        &k) == PG_SHAPE_BYPASS_UNSAFE_LITERAL);
    CHECK(pg_shape_scan("SELECT U&\"ident\" FROM t", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);

    /* float(p) precision is checked by a grammar action on the folded
       integer value (1..53 parses, 0 or 54+ errors) -> bypass */
    CHECK(pg_shape_scan("SELECT 1::float(1)", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);
    CHECK(pg_shape_scan("SELECT 1::float(55)", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);
    CHECK(pg_shape_scan("SELECT CAST(1 AS float(8))", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);
    CHECK(pg_shape_scan("SELECT float(1.5)", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_UNSAFE_LITERAL);

    /* float without a precision stays eligible */
    CHECK(pg_shape_scan("SELECT 1::float", TEST_KEY, &k) == PG_SHAPE_ELIGIBLE);
    CHECK(pg_shape_scan("SELECT 1::double precision", TEST_KEY, &k) ==
          PG_SHAPE_ELIGIBLE);

    /* empty input / comment-only -> bypass */
    CHECK(pg_shape_scan("", TEST_KEY, &k) == PG_SHAPE_BYPASS_ALLOWLIST);
    CHECK(pg_shape_scan("-- only a comment\n", TEST_KEY, &k) ==
          PG_SHAPE_BYPASS_ALLOWLIST);
}

static void
test_shape_header_participates(void)
{
    /* the context header joins the hash: a digest built by hand from only
       the token stream must differ from the scan result */
    pg_shape_key_t k;
    pg_hash_sink_t sink;
    uint8_t digest[PG_SHAPE_DIGEST_LEN];

    CHECK(scan("SELECT 1", &k));

    pg_hash_sink_init(&sink, TEST_KEY);
    pg_hash_sink_write_u8(&sink, 1); /* REC_TOKEN */
    pg_hash_sink_write_u32be(&sink, 651); /* SELECT (value from gram.h) */
    pg_hash_sink_write_u8(&sink, 0);
    pg_hash_sink_write_u8(&sink, 1); /* REC_TOKEN */
    pg_hash_sink_write_u32be(&sink, 266); /* ICONST */
    pg_hash_sink_write_u8(&sink, 0);
    pg_hash_sink_write_u8(&sink, 2); /* REC_END */
    pg_hash_sink_finalize(&sink, digest);

    CHECK(memcmp(digest, k.digest, PG_SHAPE_DIGEST_LEN) != 0);
}

/* ----------------------------------------------------------------- cache */

static pg_parse_info_t *
fake_info(uint32_t kind)
{
    pg_parse_info_t *info = malloc(sizeof(pg_parse_info_t));

    info->statement_count = 1;
    info->stmt_kinds = malloc(sizeof(uint32_t));
    info->stmt_kinds[0] = kind;
    return info;
}

static void
key_for(pg_shape_key_t *out, uint8_t seed)
{
    memset(out, 0, sizeof(*out));
    memset(out->digest, seed, PG_SHAPE_DIGEST_LEN);
    out->token_count = seed;
    out->serialized_size = seed;
}

static void
test_cache(void)
{
    pg_cache_t *c = pg_cache_create(2);
    pg_shape_key_t ka, kb, kc;
    const pg_parse_info_t *got;

    key_for(&ka, 1);
    key_for(&kb, 2);
    key_for(&kc, 3);

    CHECK(c != NULL);
    CHECK(pg_cache_insert(c, &ka, fake_info(139)));
    CHECK(pg_cache_insert(c, &kb, fake_info(135)));
    CHECK(c->entry_count == 2);

    /* hit, promoted to MRU */
    got = pg_cache_lookup(c, &ka);
    CHECK(got != NULL && got->stmt_kinds[0] == 139);
    CHECK(c->stats.hits == 1);

    /* inserting a third entry -> evicts the LRU tail (kb) */
    CHECK(pg_cache_insert(c, &kc, fake_info(138)));
    CHECK(c->entry_count == 2);
    CHECK(c->stats.evictions == 1);
    CHECK(pg_cache_lookup(c, &kb) == NULL);
    CHECK(c->stats.misses == 1);
    CHECK(pg_cache_lookup(c, &ka) != NULL); /* ka is still there */

    /* inserting the same key -> replace */
    {
        pg_parse_info_t *fresh = fake_info(139);

        fresh->stmt_kinds[0] = 999;
        CHECK(pg_cache_insert(c, &ka, fresh));
        CHECK(c->entry_count == 2);
        got = pg_cache_lookup(c, &ka);
        CHECK(got != NULL && got->stmt_kinds[0] == 999);
    }

    /* destroy does not crash */
    pg_cache_destroy(c);

    /* capacity 0 = disabled */
    c = pg_cache_create(0);
    CHECK(c != NULL);
    CHECK(pg_cache_lookup(c, &ka) == NULL);
    CHECK(!pg_cache_insert(c, &ka, fake_info(139)));
    pg_cache_destroy(c);
}

int
main(void)
{
    test_hash_sink();
    test_xxh64_kat();
    test_xxh64_streaming_consistency();
    test_shape_equivalence();
    test_shape_eligibility();
    test_shape_header_participates();
    test_cache();

    printf("%d checks, %d failures\n", checks, failures);
    if (failures == 0)
        printf("OK\n");
    return failures == 0 ? 0 : 1;
}
