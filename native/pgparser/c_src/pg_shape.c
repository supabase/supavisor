/*
 * pg_shape.c — scanner loop, token encoding and allowlist eligibility
 * checks.
 *
 * Uses the core scanner the same way libpg_query's pg_query_scan.c does:
 * scanner_init/core_yylex/scanner_finish, wrapped in PG_TRY so a longjmp
 * cannot cross the boundary; the error path does MemoryContextSwitchTo +
 * FlushErrorState.
 *
 * Scan only — no parse, no AST. This is the entire cost of the cache hit
 * path.
 */
#include "pg_shape.h"

#include <stdbool.h>
#include <string.h>

#include <pg_query.h>
#include <src/pg_query_internal.h>

#include <common/keywords.h>
#include <gramparse.h> /* scanner.h + gram.h + AST types; it guarantees order */
#include <parser/parser.h>

#include "pg_parse_info.h" /* PG_PARSE_INFO_RULES_VERSION */

#define PG_SHAPE_MAGIC 0x50475348u /* "PGSH" */
#define PG_SHAPE_FORMAT_VERSION 2u /* 2: shape hash switched to seeded XXH64 */
#define PG_SHAPE_PARSER_MAJOR 17u

/* record kinds */
#define PG_SHAPE_REC_TOKEN 1u
#define PG_SHAPE_REC_END 2u

/* token payload kinds */
#define PG_SHAPE_PAYLOAD_NONE 0u  /* keywords, single-char operators/punctuation,
                                     literals (value folded; type lives in the
                                     token code) */
#define PG_SHAPE_PAYLOAD_BYTES 1u /* IDENT/UIDENT/Op: scanner-normalized bytes */
#define PG_SHAPE_PAYLOAD_PARAM 2u /* $n: parameter number */

#define PG_SHAPE_MAX_TOKENS 1000000u
#define PG_SHAPE_MAX_PAYLOAD (1u << 20)

static void
write_context_header(pg_hash_sink_t *sink)
{
    pg_hash_sink_write_u32be(sink, PG_SHAPE_MAGIC);
    pg_hash_sink_write_u32be(sink, PG_SHAPE_FORMAT_VERSION);
    pg_hash_sink_write_u32be(sink, PG_SHAPE_PARSER_MAJOR);
    pg_hash_sink_write_u32be(sink, PG_PARSE_INFO_RULES_VERSION);
}

static bool
is_allowlisted_keyword(int tok)
{
    return tok == SELECT || tok == INSERT || tok == UPDATE ||
           tok == DELETE_P || tok == MERGE;
}

/* Encode one token into the sink; returns false on a bad payload.
 * The whole record is assembled on the stack first and written to the hash
 * in a single call (the previous implementation made 3-5 looped write
 * calls per record, the bulk of the hit path's ~15ns per-token overhead);
 * the emitted byte stream is bit-identical to it (record layout
 * unchanged). */
static bool
write_token(pg_hash_sink_t *sink, int tok, const core_YYSTYPE *yylval)
{
    uint8_t rec[10]; /* rec(1) + tok(4) + payload_kind(1) + len/ival(4) */
    size_t rec_len = 6;
    uint32_t code = (uint32_t) tok;
    const char *bytes = NULL;
    uint32_t blen = 0;

    rec[0] = PG_SHAPE_REC_TOKEN;
    rec[1] = (uint8_t) (code >> 24);
    rec[2] = (uint8_t) (code >> 16);
    rec[3] = (uint8_t) (code >> 8);
    rec[4] = (uint8_t) code;

    switch (tok)
    {
    case IDENT:
    case UIDENT:
    case Op:
        /* the scanner has already applied case folding/escape handling;
           write the bytes as-is */
        blen = (uint32_t) strlen(yylval->str);
        if (blen > PG_SHAPE_MAX_PAYLOAD)
            return false;
        rec[5] = PG_SHAPE_PAYLOAD_BYTES;
        rec[6] = (uint8_t) (blen >> 24);
        rec[7] = (uint8_t) (blen >> 16);
        rec[8] = (uint8_t) (blen >> 8);
        rec[9] = (uint8_t) blen;
        rec_len = 10;
        bytes = yylval->str;
        break;
    case PARAM:
        code = (uint32_t) yylval->ival;
        rec[5] = PG_SHAPE_PAYLOAD_PARAM;
        rec[6] = (uint8_t) (code >> 24);
        rec[7] = (uint8_t) (code >> 16);
        rec[8] = (uint8_t) (code >> 8);
        rec[9] = (uint8_t) code;
        rec_len = 10;
        break;
    default:
        rec[5] = PG_SHAPE_PAYLOAD_NONE;
        break;
    }
    pg_hash_sink_stage(sink, rec, rec_len);
    if (bytes != NULL)
        pg_hash_sink_stage(sink, bytes, blen);
    return true;
}

pg_shape_eligibility_t
pg_shape_scan(const char *sql, const uint8_t secret[PG_HASH_KEY_LEN],
              pg_shape_key_t *out)
{
    MemoryContext ctx;
    MemoryContext parse_context;
    core_yyscan_t yyscanner;
    core_yy_extra_type yyextra;
    core_YYSTYPE yylval;
    YYLTYPE yylloc;
    pg_hash_sink_t sink;
    pg_shape_eligibility_t result = PG_SHAPE_ELIGIBLE;
    uint32_t token_count = 0;
    int first_tok = 0;
    int prev_tok = 0;
    bool pending_boundary = false;

    ctx = pg_query_enter_memory_context();
    parse_context = CurrentMemoryContext;

    pg_hash_sink_init(&sink, secret);
    write_context_header(&sink);

    /* scanner behavior consistent with pg_query_raw_parse (__thread GUCs) */
    backslash_quote = BACKSLASH_QUOTE_SAFE_ENCODING;
    standard_conforming_strings = true;
    escape_string_warning = true;

    PG_TRY();
    {
        yyscanner = scanner_init(sql, &yyextra, &ScanKeywords,
                                 ScanKeywordTokens);
        for (;;)
        {
            int tok = core_yylex(&yylval, &yylloc, yyscanner);

            if (tok == 0) /* EOF */
            {
                if (first_tok == 0)
                    result = PG_SHAPE_BYPASS_ALLOWLIST; /* empty input / comment only */
                pg_hash_sink_write_u8(&sink, PG_SHAPE_REC_END);
                break;
            }
            if (tok == C_COMMENT || tok == SQL_COMMENT)
                continue; /* comments do not join the shape */
            if (tok == ';')
            {
                /* defer the boundary write: extra trailing semicolons are
                   uniformly ignored */
                pending_boundary = true;
                continue;
            }
            if (pending_boundary)
            {
                /* a substantive token after ';' -> multiple statements */
                result = PG_SHAPE_BYPASS_MULTI_STATEMENT;
                break;
            }
            if (first_tok == 0)
            {
                first_tok = tok;
                if (!is_allowlisted_keyword(tok))
                {
                    result = PG_SHAPE_BYPASS_ALLOWLIST;
                    break;
                }
            }
            if (++token_count > PG_SHAPE_MAX_TOKENS)
            {
                result = PG_SHAPE_BYPASS_SCAN_ERROR;
                break;
            }
            if (tok == USCONST || tok == UIDENT)
            {
                /* U&'...' / U&"..." bodies and any UESCAPE clause are
                   validated by the parser's token-filter layer
                   (str_udeescape / check_uescapechar), not by the core
                   scanner: identical token shapes can parse or fail
                   depending on folded literal content. Bypass the cache
                   for them. */
                result = PG_SHAPE_BYPASS_UNSAFE_LITERAL;
                break;
            }
            if (tok == '(' && prev_tok == FLOAT_P)
            {
                /* float(p) maps to float4/float8 in a grammar action based
                   on the folded integer value (1..53 parses, 0 or 54+
                   errors): same-shape queries can differ in parse success.
                   Bypass the cache for them. */
                result = PG_SHAPE_BYPASS_UNSAFE_LITERAL;
                break;
            }
            if (!write_token(&sink, tok, &yylval))
            {
                result = PG_SHAPE_BYPASS_SCAN_ERROR;
                break;
            }
            prev_tok = tok;
        }
        scanner_finish(yyscanner);
    }
    PG_CATCH();
    {
        MemoryContextSwitchTo(parse_context);
        FlushErrorState();
        result = PG_SHAPE_BYPASS_SCAN_ERROR;
    }
    PG_END_TRY();

    pg_query_exit_memory_context(ctx);

    if (result == PG_SHAPE_ELIGIBLE)
    {
        out->token_count = token_count;
        out->serialized_size = sink.serialized_size;
        pg_hash_sink_finalize(&sink, out->digest);
    }
    return result;
}
