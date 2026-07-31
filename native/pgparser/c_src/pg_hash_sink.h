/*
 * pg_hash_sink.h — stable sink-oriented binary writes + seeded XXH64
 * incremental hashing.
 *
 * Only explicit fields are written (big-endian integers, tag+len+bytes);
 * raw struct memory is never hashed, keeping results stable across
 * platforms/compilers.
 *
 * The seed derives from 32 bytes of per-boot random material (see
 * pg_hash_sink_init). XXH64 is not a keyed/MAC construction: the seed is a
 * best-effort cache-poisoning deterrent only, not a cryptographic
 * guarantee. The threat model of this cache explicitly excludes adversarial
 * collision crafting; 64-bit random collisions are negligible at the
 * intended cache sizes (~2.7e-12 at 1e4 entries).
 */
#ifndef PG_HASH_SINK_H
#define PG_HASH_SINK_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "xxh64.h"

#define PG_SHAPE_DIGEST_LEN 8 /* XXH64 */
#define PG_HASH_KEY_LEN 32    /* per-boot random seed material */

typedef struct pg_hash_sink
{
    XXH64_state_t state;
    uint32_t serialized_size; /* total bytes written */
} pg_hash_sink_t;

/* Fast path: straight into the XXH64 state (it maintains its own 32-byte
 * internal buffer; a staging layer on top would only add a memcpy). The
 * shape encoder calls this 1-2 times per token, so its call overhead is one
 * of the main costs of the hit path — keeping it inline matters. */
static inline void
pg_hash_sink_stage(pg_hash_sink_t *sink, const void *data, size_t len)
{
    sink->serialized_size += (uint32_t) len;
    (void) XXH64_update(&sink->state, data, len);
}

void pg_hash_sink_init(pg_hash_sink_t *sink, const uint8_t key[PG_HASH_KEY_LEN]);
void pg_hash_sink_write_u8(pg_hash_sink_t *sink, uint8_t value);
void pg_hash_sink_write_u32be(pg_hash_sink_t *sink, uint32_t value);
void pg_hash_sink_write_u64be(pg_hash_sink_t *sink, uint64_t value);
void pg_hash_sink_write_bytes(pg_hash_sink_t *sink, const void *data, size_t len);
void pg_hash_sink_finalize(pg_hash_sink_t *sink, uint8_t out[PG_SHAPE_DIGEST_LEN]);

#endif /* PG_HASH_SINK_H */
