use rustler::{Atom, Error as RustlerError, NifTuple};

mod atoms {
    rustler::atoms! {
      ok,
      error,
    }
}

#[derive(NifTuple)]
struct Response {
    status: Atom,
    message: Vec<String>
}

#[rustler::nif]
fn statement_types(query: &str) -> Result<Response, RustlerError> {
    let result = pg_query::parse(&query);

    if let Ok(result) = result {
        let message = result.statement_types().into_iter().map(|s| s.to_string()).collect();
        return Ok(Response{status: atoms::ok(), message});
    } else {
        return Err(RustlerError::Term(Box::new("Error parsing query")));
    }
}

rustler::init!("Elixir.Supavisor.PgParser", [statement_types]);
