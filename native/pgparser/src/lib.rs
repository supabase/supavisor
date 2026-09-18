use rustler::{Resource, ResourceArc};

/// A parsed query tree, kept alive across NIF calls so that several checks can
/// walk it without re-parsing. `pg_query::ParseResult` owns all of its data
/// (the C-side allocation is freed inside `pg_query::parse`), so it is safe to
/// hold here.
struct ParsedQuery {
    result: pg_query::ParseResult,
}

#[rustler::resource_impl]
impl Resource for ParsedQuery {}

fn statement_types_of(result: &pg_query::ParseResult) -> Vec<String> {
    result
        .statement_types()
        .into_iter()
        .map(Into::into)
        .collect()
}

fn has_session_set_of(result: &pg_query::ParseResult) -> bool {
    result.protobuf.stmts.iter().any(|raw_stmt| {
        match raw_stmt.stmt.as_deref().and_then(|node| node.node.as_ref()) {
            Some(pg_query::NodeEnum::VariableSetStmt(stmt)) => {
                // SET LOCAL, SET TRANSACTION and SET TRANSACTION SNAPSHOT are
                // transaction-scoped, so they are safe in transaction mode
                !stmt.is_local && stmt.name != "TRANSACTION" && stmt.name != "TRANSACTION SNAPSHOT"
            }
            _ => false,
        }
    })
}

#[rustler::nif]
fn statement_types(query: &str) -> Result<Vec<String>, String> {
    let result = pg_query::parse(query).map_err(|_| "Error parsing query")?;

    Ok(statement_types_of(&result))
}

#[rustler::nif]
fn has_session_set(query: &str) -> Result<bool, String> {
    let result = pg_query::parse(query).map_err(|_| "Error parsing query")?;

    Ok(has_session_set_of(&result))
}

/// Parses a query into a tree that can be inspected by the functions below.
///
/// Parsing dominates the cost of every check, so callers that run more than
/// one check should parse once here and reuse the result.
#[rustler::nif]
fn parse(query: &str) -> Result<ResourceArc<ParsedQuery>, String> {
    let result = pg_query::parse(query).map_err(|_| "Error parsing query")?;

    Ok(ResourceArc::new(ParsedQuery { result }))
}

#[rustler::nif]
fn parsed_statement_types(parsed: ResourceArc<ParsedQuery>) -> Vec<String> {
    statement_types_of(&parsed.result)
}

#[rustler::nif]
fn parsed_has_session_set(parsed: ResourceArc<ParsedQuery>) -> bool {
    has_session_set_of(&parsed.result)
}

rustler::init!("Elixir.Supavisor.PgParser");
