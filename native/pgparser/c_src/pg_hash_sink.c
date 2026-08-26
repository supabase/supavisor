#include "pg_hash_sink.h"

#include <string.h>

void
pg_hash_sink_init(pg_hash_sink_t *sink, const uint8_t key[PG_HASH_KEY_LEN])
{
    /* Fold the 32-byte random material into the 64-bit XXH64 seed so every
       byte influences the seed. An all-zero key yields seed 0, which matches
       upstream's published test vectors (used by the C unit tests). */
    uint64_t seed = 0;
    int i;

    for (i = 0; i < PG_HASH_KEY_LEN / 8; i++)
    {
        uint64_t w;

        memcpy(&w, key + i * 8, sizeof(w));
        seed ^= w;
    }
    (void) XXH64_reset(&sink->state, seed);
    sink->serialized_size = 0;
}

void
pg_hash_sink_write_u8(pg_hash_sink_t *sink, uint8_t value)
{
    pg_hash_sink_stage(sink, &value, 1);
}

void
pg_hash_sink_write_u32be(pg_hash_sink_t *sink, uint32_t value)
{
    uint8_t buf[4];

    buf[0] = (uint8_t) (value >> 24);
    buf[1] = (uint8_t) (value >> 16);
    buf[2] = (uint8_t) (value >> 8);
    buf[3] = (uint8_t) value;
    pg_hash_sink_stage(sink, buf, sizeof(buf));
}

void
pg_hash_sink_write_u64be(pg_hash_sink_t *sink, uint64_t value)
{
    uint8_t buf[8];
    int i;

    for (i = 7; i >= 0; i--)
    {
        buf[i] = (uint8_t) value;
        value >>= 8;
    }
    pg_hash_sink_stage(sink, buf, sizeof(buf));
}

void
pg_hash_sink_write_bytes(pg_hash_sink_t *sink, const void *data, size_t len)
{
    pg_hash_sink_stage(sink, data, len);
}

void
pg_hash_sink_finalize(pg_hash_sink_t *sink, uint8_t out[PG_SHAPE_DIGEST_LEN])
{
    /* big-endian canonical form: stable digest bytes across platforms */
    XXH64_canonical_t canon;

    XXH64_canonicalFromHash(&canon, XXH64_digest(&sink->state));
    memcpy(out, canon.digest, PG_SHAPE_DIGEST_LEN);
}
