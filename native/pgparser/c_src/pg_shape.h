/*
 * pg_shape.h — stream a SQL statement's ShapeKey from the PostgreSQL core
 * scanner.
 *
 * Invariant: two SQL strings may map to the same hittable shape only when
 * they are guaranteed to produce the same result under the current
 * ParseInfo rules. Keywords, identifiers, operators, parameter numbers
 * and statement boundaries all join the shape; only literal *values* are
 * folded (their type tag is kept); comments and whitespace are skipped by
 * the scanner itself; extra trailing semicolons are uniformly ignored.
 * Exception: literal content that is validated only at parse time never
 * joins a shape — unicode literals (U&'...' / U&"..." plus any UESCAPE
 * clause, checked by the parser's token-filter layer, not the core
 * scanner) and float(p) precisions (checked by a grammar action on the
 * folded integer value). Folded values could flip such a parse from
 * success to error, so these queries bypass the cache.
 */
#ifndef PG_SHAPE_H
#define PG_SHAPE_H

#include <stdint.h>

#include "pg_hash_sink.h"

typedef struct pg_shape_key
{
    uint8_t digest[PG_SHAPE_DIGEST_LEN];
    uint32_t token_count;     /* number of encoded tokens (extra check) */
    uint32_t serialized_size; /* number of encoded bytes (extra check) */
} pg_shape_key_t;

typedef enum pg_shape_eligibility
{
    PG_SHAPE_ELIGIBLE = 0,          /* single-statement allowlist family, cacheable */
    PG_SHAPE_BYPASS_ALLOWLIST,       /* first keyword outside the allowlist */
    PG_SHAPE_BYPASS_MULTI_STATEMENT, /* multiple statements */
    PG_SHAPE_BYPASS_SCAN_ERROR,      /* scanner error / unexpected token / overflow */
    PG_SHAPE_BYPASS_UNSAFE_LITERAL   /* folded literal content validated only
                                        at parse time (unicode literals via
                                        the parser's token-filter layer,
                                        float(p) precision via a grammar
                                        action), so it cannot join a shape */
} pg_shape_eligibility_t;

/*
 * Scan sql (NUL-terminated), streaming a ShapeKey.
 * secret is 32 bytes of per-boot random material folded into the hash seed
 * (best-effort poisoning resistance; not cryptographic). out is valid when
 * PG_SHAPE_ELIGIBLE is returned; any other return value reports why the
 * cache is bypassed.
 */
pg_shape_eligibility_t pg_shape_scan(const char *sql,
                                     const uint8_t secret[PG_HASH_KEY_LEN],
                                     pg_shape_key_t *out);

#endif /* PG_SHAPE_H */
