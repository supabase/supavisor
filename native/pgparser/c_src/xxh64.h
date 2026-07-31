/*
 * xxh64.h — XXH64 (64-bit xxHash) streaming hash, header-only.
 *
 * Verbatim extraction from xxHash v0.8.3 (xxhash.h), XXH64 sections only.
 * Upstream license (BSD 2-Clause) reproduced below as required:
 *
 * ---------------------------------------------------------------------------
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2012-2023 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ---------------------------------------------------------------------------
 *
 * Extraction notes (no algorithm code was modified):
 * - removed the XXH32 and XXH3 families, MSVC paths, XXH_OLD_NAMES aliases,
 *   XXH_FORCE_MEMORY_ACCESS/XXH_FORCE_ALIGN_CHECK tuning knobs, heap state
 *   helpers (XXH64_createState/freeState/copyState) and verbose Doxygen
 *   comments;
 * - the AVX512 auto-vectorization guard inside XXH64_round was dropped
 *   (a no-op unless built with -mavx512f, which this project never does);
 * - memory reads keep the upstream default portable path (memcpy-based);
 * - XXH64() one-shot always uses the XXH_unaligned path, matching the
 *   upstream default build (XXH_FORCE_ALIGN_CHECK=0);
 * - everything is "static"/"static inline", so this header can be included
 *   from multiple translation units.
 * Correctness is pinned by known-answer tests against upstream's official
 * sanity vectors (tests/sanity_test_vectors.h) — see test/shape_cache_tests.c.
 */
#ifndef PG_XXH64_H
#define PG_XXH64_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t xxh_u8;
typedef uint32_t xxh_u32;
typedef uint64_t xxh_u64;
typedef uint32_t XXH32_hash_t;
typedef uint64_t XXH64_hash_t;

typedef enum { XXH_OK = 0, XXH_ERROR } XXH_errorcode;

/* ------------------------------------------------ upstream scaffolding */
#define XXH_GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)

#ifdef __has_builtin
#define XXH_HAS_BUILTIN(x) __has_builtin(x)
#else
#define XXH_HAS_BUILTIN(x) 0
#endif

#define XXH_FORCE_INLINE static inline __attribute__((always_inline))
#define XXH_STATIC static
#define XXH_PUREF __attribute__((pure))
#define XXH_NOESCAPE
#define XXH_RESTRICT restrict
#define XXH_memcpy memcpy
#define XXH_ASSERT(c) ((void) 0)
#define XXH_STATIC_ASSERT(c) _Static_assert(c, "")

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&           \
    defined(__ORDER_BIG_ENDIAN__)
#define XXH_CPU_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#else
/* upstream portable runtime fallback */
static int
XXH_isLittleEndian(void)
{
    const union
    {
        xxh_u32 u;
        xxh_u8 c[4];
    } one = {1};
    return one.c[0];
}
#define XXH_CPU_LITTLE_ENDIAN XXH_isLittleEndian()
#endif

#if !defined(NO_CLANG_BUILTIN) && XXH_HAS_BUILTIN(__builtin_rotateleft64)
#define XXH_rotl64 __builtin_rotateleft64
#elif XXH_HAS_BUILTIN(__builtin_stdc_rotate_left)
#define XXH_rotl64 __builtin_stdc_rotate_left
#else
#define XXH_rotl64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))
#endif

#if XXH_GCC_VERSION >= 403
#define XXH_swap32 __builtin_bswap32
#define XXH_swap64 __builtin_bswap64
#else
static xxh_u32
XXH_swap32(xxh_u32 x)
{
    return ((x << 24) & 0xff000000) | ((x << 8) & 0x00ff0000) |
           ((x >> 8) & 0x0000ff00) | ((x >> 24) & 0x000000ff);
}
static xxh_u64
XXH_swap64(xxh_u64 x)
{
    return ((x << 56) & 0xff00000000000000ULL) |
           ((x << 40) & 0x00ff000000000000ULL) |
           ((x << 24) & 0x0000ff0000000000ULL) |
           ((x << 8) & 0x000000ff00000000ULL) |
           ((x >> 8) & 0x00000000ff000000ULL) |
           ((x >> 24) & 0x0000000000ff0000ULL) |
           ((x >> 40) & 0x000000000000ff00ULL) |
           ((x >> 56) & 0x00000000000000ffULL);
}
#endif

typedef enum
{
    XXH_aligned,
    XXH_unaligned
} XXH_alignment;

/* ------------------------------------------------ memory reads (verbatim,
 * portable default path) */
static xxh_u32
XXH_read32(const void *memPtr)
{
    xxh_u32 val;
    XXH_memcpy(&val, memPtr, sizeof(val));
    return val;
}

static xxh_u64
XXH_read64(const void *memPtr)
{
    xxh_u64 val;
    XXH_memcpy(&val, memPtr, sizeof(val));
    return val;
}

XXH_FORCE_INLINE xxh_u32
XXH_readLE32(const void *ptr)
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_read32(ptr) : XXH_swap32(XXH_read32(ptr));
}

XXH_FORCE_INLINE xxh_u64
XXH_readLE64(const void *ptr)
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_read64(ptr) : XXH_swap64(XXH_read64(ptr));
}

XXH_FORCE_INLINE xxh_u32
XXH_readLE32_align(const void *ptr, XXH_alignment align)
{
    if (align == XXH_unaligned)
    {
        return XXH_readLE32(ptr);
    }
    else
    {
        return XXH_CPU_LITTLE_ENDIAN ? *(const xxh_u32 *) ptr
                                     : XXH_swap32(*(const xxh_u32 *) ptr);
    }
}

XXH_FORCE_INLINE xxh_u64
XXH_readLE64_align(const void *ptr, XXH_alignment align)
{
    if (align == XXH_unaligned)
        return XXH_readLE64(ptr);
    else
        return XXH_CPU_LITTLE_ENDIAN ? *(const xxh_u64 *) ptr
                                     : XXH_swap64(*(const xxh_u64 *) ptr);
}

#define XXH_get32bits(p) XXH_readLE32_align(p, align)
#define XXH_get64bits(p) XXH_readLE64_align(p, align)

/* ------------------------------------------------ XXH64 core (verbatim) */
#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

static xxh_u64
XXH64_round(xxh_u64 acc, xxh_u64 input)
{
    acc += input * XXH_PRIME64_2;
    acc = XXH_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static xxh_u64
XXH64_mergeRound(xxh_u64 acc, xxh_u64 val)
{
    val = XXH64_round(0, val);
    acc ^= val;
    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static xxh_u64
XXH64_avalanche(xxh_u64 hash)
{
    hash ^= hash >> 33;
    hash *= XXH_PRIME64_2;
    hash ^= hash >> 29;
    hash *= XXH_PRIME64_3;
    hash ^= hash >> 32;
    return hash;
}

XXH_FORCE_INLINE void
XXH64_initAccs(xxh_u64 *acc, xxh_u64 seed)
{
    XXH_ASSERT(acc != NULL);
    acc[0] = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
    acc[1] = seed + XXH_PRIME64_2;
    acc[2] = seed + 0;
    acc[3] = seed - XXH_PRIME64_1;
}

XXH_FORCE_INLINE const xxh_u8 *
XXH64_consumeLong(xxh_u64 *XXH_RESTRICT acc, const xxh_u8 *XXH_RESTRICT input,
                  size_t len, XXH_alignment align)
{
    const xxh_u8 *const bEnd = input + len;
    const xxh_u8 *const limit = bEnd - 31;
    XXH_ASSERT(acc != NULL);
    XXH_ASSERT(input != NULL);
    XXH_ASSERT(len >= 32);
    do
    {
        /* reroll on 32-bit */
        if (sizeof(void *) < sizeof(xxh_u64))
        {
            size_t i;
            for (i = 0; i < 4; i++)
            {
                acc[i] = XXH64_round(acc[i], XXH_get64bits(input));
                input += 8;
            }
        }
        else
        {
            acc[0] = XXH64_round(acc[0], XXH_get64bits(input));
            input += 8;
            acc[1] = XXH64_round(acc[1], XXH_get64bits(input));
            input += 8;
            acc[2] = XXH64_round(acc[2], XXH_get64bits(input));
            input += 8;
            acc[3] = XXH64_round(acc[3], XXH_get64bits(input));
            input += 8;
        }
    } while (input < limit);

    return input;
}

XXH_FORCE_INLINE XXH_PUREF xxh_u64
XXH64_mergeAccs(const xxh_u64 *acc)
{
    XXH_ASSERT(acc != NULL);
    {
        xxh_u64 h64 = XXH_rotl64(acc[0], 1) + XXH_rotl64(acc[1], 7) +
                      XXH_rotl64(acc[2], 12) + XXH_rotl64(acc[3], 18);
        /* reroll on 32-bit */
        if (sizeof(void *) < sizeof(xxh_u64))
        {
            size_t i;
            for (i = 0; i < 4; i++)
            {
                h64 = XXH64_mergeRound(h64, acc[i]);
            }
        }
        else
        {
            h64 = XXH64_mergeRound(h64, acc[0]);
            h64 = XXH64_mergeRound(h64, acc[1]);
            h64 = XXH64_mergeRound(h64, acc[2]);
            h64 = XXH64_mergeRound(h64, acc[3]);
        }
        return h64;
    }
}

XXH_STATIC XXH_PUREF xxh_u64
XXH64_finalize(xxh_u64 hash, const xxh_u8 *ptr, size_t len, XXH_alignment align)
{
    if (ptr == NULL)
        XXH_ASSERT(len == 0);
    len &= 31;
    while (len >= 8)
    {
        xxh_u64 const k1 = XXH64_round(0, XXH_get64bits(ptr));
        ptr += 8;
        hash ^= k1;
        hash = XXH_rotl64(hash, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        len -= 8;
    }
    if (len >= 4)
    {
        hash ^= (xxh_u64) (XXH_get32bits(ptr)) * XXH_PRIME64_1;
        ptr += 4;
        hash = XXH_rotl64(hash, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        len -= 4;
    }
    while (len > 0)
    {
        hash ^= (*ptr++) * XXH_PRIME64_5;
        hash = XXH_rotl64(hash, 11) * XXH_PRIME64_1;
        --len;
    }
    return XXH64_avalanche(hash);
}

XXH_FORCE_INLINE XXH_PUREF xxh_u64
XXH64_endian_align(const xxh_u8 *input, size_t len, xxh_u64 seed,
                   XXH_alignment align)
{
    xxh_u64 h64;
    if (input == NULL)
        XXH_ASSERT(len == 0);

    if (len >= 32)
    {
        xxh_u64 acc[4];
        XXH64_initAccs(acc, seed);

        input = XXH64_consumeLong(acc, input, len, align);

        h64 = XXH64_mergeAccs(acc);
    }
    else
    {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += (xxh_u64) len;

    return XXH64_finalize(h64, input, len, align);
}

XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
XXH64(XXH_NOESCAPE const void *input, size_t len, XXH64_hash_t seed)
{
    /* upstream default build (XXH_FORCE_ALIGN_CHECK=0): always unaligned */
    return XXH64_endian_align((const xxh_u8 *) input, len, seed, XXH_unaligned);
}

/* ------------------------------------------------ streaming state (verbatim) */
typedef struct XXH64_state_s
{
    XXH64_hash_t total_len;
    XXH64_hash_t acc[4];
    unsigned char buffer[32];
    XXH32_hash_t bufferedSize;
    XXH32_hash_t reserved32;
    XXH64_hash_t reserved64;
} XXH64_state_t;

XXH_FORCE_INLINE XXH_errorcode
XXH64_reset(XXH_NOESCAPE XXH64_state_t *statePtr, XXH64_hash_t seed)
{
    XXH_ASSERT(statePtr != NULL);
    memset(statePtr, 0, sizeof(*statePtr));
    XXH64_initAccs(statePtr->acc, seed);
    return XXH_OK;
}

XXH_FORCE_INLINE XXH_errorcode
XXH64_update(XXH_NOESCAPE XXH64_state_t *state, XXH_NOESCAPE const void *input,
             size_t len)
{
    if (input == NULL)
    {
        XXH_ASSERT(len == 0);
        return XXH_OK;
    }

    state->total_len += len;

    XXH_ASSERT(state->bufferedSize <= sizeof(state->buffer));
    if (len < sizeof(state->buffer) - state->bufferedSize)
    { /* fill in tmp buffer */
        XXH_memcpy(state->buffer + state->bufferedSize, input, len);
        state->bufferedSize += (XXH32_hash_t) len;
        return XXH_OK;
    }

    {
        const xxh_u8 *xinput = (const xxh_u8 *) input;
        const xxh_u8 *const bEnd = xinput + len;

        if (state->bufferedSize)
        { /* non-empty buffer => complete first */
            XXH_memcpy(state->buffer + state->bufferedSize, xinput,
                       sizeof(state->buffer) - state->bufferedSize);
            xinput += sizeof(state->buffer) - state->bufferedSize;
            /* and process one round */
            (void) XXH64_consumeLong(state->acc, state->buffer,
                                     sizeof(state->buffer), XXH_aligned);
            state->bufferedSize = 0;
        }

        XXH_ASSERT(xinput <= bEnd);
        if ((size_t) (bEnd - xinput) >= sizeof(state->buffer))
        {
            /* Process the remaining data */
            xinput = XXH64_consumeLong(state->acc, xinput,
                                       (size_t) (bEnd - xinput), XXH_unaligned);
        }

        if (xinput < bEnd)
        {
            /* Copy the leftover to the tmp buffer */
            XXH_memcpy(state->buffer, xinput, (size_t) (bEnd - xinput));
            state->bufferedSize = (unsigned) (bEnd - xinput);
        }
    }

    return XXH_OK;
}

XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
XXH64_digest(XXH_NOESCAPE const XXH64_state_t *state)
{
    xxh_u64 h64;

    if (state->total_len >= 32)
    {
        h64 = XXH64_mergeAccs(state->acc);
    }
    else
    {
        h64 = state->acc[2] /*seed*/ + XXH_PRIME64_5;
    }

    h64 += (xxh_u64) state->total_len;

    return XXH64_finalize(h64, state->buffer, (size_t) state->total_len,
                          XXH_aligned);
}

/* ------------------------------------- canonical representation (verbatim) */
typedef struct
{
    unsigned char digest[8];
} XXH64_canonical_t;

XXH_FORCE_INLINE void
XXH64_canonicalFromHash(XXH_NOESCAPE XXH64_canonical_t *dst, XXH64_hash_t hash)
{
    XXH_STATIC_ASSERT(sizeof(XXH64_canonical_t) == sizeof(XXH64_hash_t));
    if (XXH_CPU_LITTLE_ENDIAN)
        hash = XXH_swap64(hash);
    XXH_memcpy(dst, &hash, sizeof(*dst));
}

XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
XXH64_hashFromCanonical(XXH_NOESCAPE const XXH64_canonical_t *src)
{
    xxh_u64 h;
    XXH_memcpy(&h, src, sizeof(h));
    return XXH_CPU_LITTLE_ENDIAN ? XXH_swap64(h) : h;
}

#endif /* PG_XXH64_H */
