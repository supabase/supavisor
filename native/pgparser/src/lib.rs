#[rustler::nif]
fn statement_types(query: &str) -> Result<Vec<String>, String> {
    let result = pg_query::parse(query).map_err(|_| "Error parsing query")?;

    let message = result
        .statement_types()
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(message)
}

#[rustler::nif]
fn has_session_set(query: &str) -> Result<bool, String> {
    let result = pg_query::parse(query).map_err(|_| "Error parsing query")?;

    let found = result.protobuf.stmts.iter().any(|raw_stmt| {
        match raw_stmt.stmt.as_deref().and_then(|node| node.node.as_ref()) {
            Some(pg_query::NodeEnum::VariableSetStmt(stmt)) => {
                // SET LOCAL, SET TRANSACTION and SET TRANSACTION SNAPSHOT are
                // transaction-scoped, so they are safe in transaction mode
                !stmt.is_local && stmt.name != "TRANSACTION" && stmt.name != "TRANSACTION SNAPSHOT"
            }
            _ => false,
        }
    });

    Ok(found)
}

rustler::init!("Elixir.Supavisor.PgParser");
