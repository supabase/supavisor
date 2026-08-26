/*
 * pg_parse_info.c — follows the MaxScale pp_pg_query pattern:
 * pg_query_enter_memory_context() -> pg_query_raw_parse() -> walk the raw
 * AST (RawStmt list) -> copy out into owned memory ->
 * pg_query_exit_memory_context(). Error handling (PG_TRY/longjmp) is done
 * inside libpg_query and never crosses out of this module.
 */
#include "pg_parse_info.h"

#include <stdlib.h>

#include <pg_query.h>
#include <src/pg_query_internal.h>

#include <nodes/nodes.h>
#include <nodes/parsenodes.h>
#include <nodes/pg_list.h>

const char *
pg_nodetag_name(uint32_t tag)
{
    switch (tag)
    {
#include "pg_nodetags.inc"
    default:
        return NULL;
    }
}

bool
pg_parse_info_build(const char *sql, pg_parse_info_t **out)
{
    MemoryContext ctx;
    PgQueryInternalParsetreeAndError result;
    pg_parse_info_t *info;
    ListCell *lc;
    uint32_t i;

    ctx = pg_query_enter_memory_context();
    result = pg_query_raw_parse(sql, PG_QUERY_PARSE_DEFAULT);

    if (result.error != NULL)
    {
        pg_query_free_error(result.error);
        free(result.stderr_buffer);
        pg_query_exit_memory_context(ctx);
        return false;
    }

    /* tree == NULL with no error: empty input / comment-only, which is
       valid — treat as 0 statements (the contract requires {:ok, []},
       matching the old pg_query.rs behavior) */
    info = malloc(sizeof(pg_parse_info_t));
    if (info == NULL)
    {
        free(result.stderr_buffer);
        pg_query_exit_memory_context(ctx);
        return false;
    }

    info->statement_count = (uint32_t) list_length(result.tree);
    info->stmt_kinds = NULL;
    if (info->statement_count > 0)
    {
        info->stmt_kinds = malloc(sizeof(uint32_t) * info->statement_count);
        if (info->stmt_kinds == NULL)
        {
            free(info);
            free(result.stderr_buffer);
            pg_query_exit_memory_context(ctx);
            return false;
        }
    }

    i = 0;
    foreach (lc, result.tree)
    {
        RawStmt *raw = (RawStmt *) lfirst(lc);
        info->stmt_kinds[i++] = (uint32_t) nodeTag(raw->stmt);
    }

    /* stderr_buffer is malloc'd (always an empty string unless DEBUG is
       defined) and must be freed */
    free(result.stderr_buffer);
    pg_query_exit_memory_context(ctx);

    *out = info;
    return true;
}

void
pg_parse_info_free(pg_parse_info_t *info)
{
    if (info == NULL)
        return;
    free(info->stmt_kinds);
    free(info);
}
