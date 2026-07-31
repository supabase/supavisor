/*
 * pg_parse_info.h — statement information extracted from one raw parse
 * (QueryInfo, minimal set).
 *
 * When more information is needed in the future (read/write
 * classification, table names, ...), add fields to pg_parse_info_t and
 * bump PG_PARSE_INFO_RULES_VERSION.
 */
#ifndef PG_PARSE_INFO_H
#define PG_PARSE_INFO_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Classification/extraction rules version. Any code change that could
 * alter parse results (including QueryInfo field changes) must bump it:
 * the value joins every shape key's context header, so old cache keys
 * expire automatically.
 */
#define PG_PARSE_INFO_RULES_VERSION 1

typedef struct pg_parse_info
{
    uint32_t statement_count;
    uint32_t *stmt_kinds; /* malloc-owned NodeTag array, length == statement_count */
} pg_parse_info_t;

/*
 * Run one PostgreSQL raw parse over sql (NUL-terminated).
 * On success returns true with *out pointing at a malloc'd
 * pg_parse_info_t (caller must pg_parse_info_free); on failure returns
 * false (details are deliberately not propagated, per the interface
 * contract).
 */
bool pg_parse_info_build(const char *sql, pg_parse_info_t **out);
void pg_parse_info_free(pg_parse_info_t *info);

/* NodeTag -> node name ("SelectStmt", protobuf-compatible naming). NULL for
 * unknown tags. */
const char *pg_nodetag_name(uint32_t tag);

#endif /* PG_PARSE_INFO_H */
