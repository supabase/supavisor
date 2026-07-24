use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

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

// The `pg_query` Rust crate exposes only the protobuf variant of the parser, hence using C lib directly.
// TODO: Move to rust-only once the serializer is officially released.
// Ref: https://github.com/pganalyze/pg_query.rs/commit/123d448c10f91b33de165f00d5638ce80759aa9c

/// https://github.com/pganalyze/libpg_query/blob/17-6.1.0/pg_query.h#L7-L14
#[repr(C)]
struct PgQueryError {
    message: *mut c_char,
    funcname: *mut c_char,
    filename: *mut c_char,
    lineno: c_int,
    cursorpos: c_int,
    context: *mut c_char,
}

/// https://github.com/pganalyze/libpg_query/blob/17-6.1.0/pg_query.h#L27-L31
#[repr(C)]
struct PgQueryParseResult {
    parse_tree: *mut c_char,
    stderr_buffer: *mut c_char,
    error: *mut PgQueryError,
}

extern "C" {
    /// https://github.com/pganalyze/libpg_query/blob/17-6.1.0/pg_query.h#L101
    fn pg_query_parse(input: *const c_char) -> PgQueryParseResult;

    /// https://github.com/pganalyze/libpg_query/blob/17-6.1.0/pg_query.h#L124
    fn pg_query_free_parse_result(result: PgQueryParseResult);
}

#[rustler::nif]
fn parse_to_json(query: &str) -> Result<String, String> {
    let input = CString::new(query).map_err(|_| "input contains null byte".to_string())?;
    let result = unsafe { pg_query_parse(input.as_ptr()) };

    let outcome = if result.error.is_null() {
        let json = unsafe { CStr::from_ptr(result.parse_tree) }
            .to_string_lossy()
            .into_owned();
        Ok(json)
    } else {
        let msg = unsafe { CStr::from_ptr((*result.error).message) }
            .to_string_lossy()
            .into_owned();
        Err(msg)
    };

    unsafe { pg_query_free_parse_result(result) };
    outcome
}

rustler::init!("Elixir.Supavisor.PgParser");
