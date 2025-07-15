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
fn fingerprint(query: &str) -> Result<String, String> {
    pg_query::fingerprint(query)
        .map(|fingerprint| Ok(fingerprint.hex))
        .map_err(|_| "Error fingerprinting query")?
}

rustler::init!("Elixir.Supavisor.PgParser");
