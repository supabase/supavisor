use rustler::{Atom, Resource, ResourceArc};

mod atoms {
    rustler::atoms! {
        nil,
        session_set,
        set_config,
        discard,
        advisory_lock,
        listen,
        hold_cursor,
        temp_table,
        set_constraints,
        load,
    }
}

/// A parsed query tree, kept alive across NIF calls so that several checks can
/// walk it without re-parsing. `pg_query::ParseResult` owns all of its data
/// (the C-side allocation is freed inside `pg_query::parse`), so it is safe to
/// hold here.
struct ParsedQuery {
    result: pg_query::ParseResult,
}

#[rustler::resource_impl]
impl Resource for ParsedQuery {}

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
fn statement_types(parsed: ResourceArc<ParsedQuery>) -> Vec<String> {
    parsed
        .result
        .statement_types()
        .into_iter()
        .map(Into::into)
        .collect()
}

/// `WITH HOLD`, from libpg_query's `CURSOR_OPT_HOLD`. A cursor declared with it
/// survives the commit that would otherwise close it.
const CURSOR_OPT_HOLD: i32 = 0x0020;

/// `OnCommitAction::OncommitDrop`. A temp table created with `ON COMMIT DROP`
/// does not outlive the transaction.
const ONCOMMIT_DROP: i32 = 4;

/// Functions that change a session GUC. `set_config`'s third argument decides
/// whether the change is transaction-local, so it is checked separately.
const SET_CONFIG: &str = "set_config";

/// Advisory lock functions whose locks are held until the session ends. The
/// `_xact_` variants are released on commit and so are absent here.
const SESSION_ADVISORY_LOCK_FUNCS: [&str; 6] = [
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_advisory_unlock",
    "pg_advisory_unlock_all",
];

/// Returns the kind of state the first leaking statement leaves on the backend,
/// or `nil` when the query leaks none.
#[rustler::nif]
fn session_leak(parsed: ResourceArc<ParsedQuery>) -> Atom {
    parsed
        .result
        .protobuf
        .stmts
        .iter()
        .filter_map(|raw_stmt| raw_stmt.stmt.as_deref().and_then(|node| node.node.as_ref()))
        .find_map(statement_leak)
        .unwrap_or_else(atoms::nil)
}

/// The state a statement leaves on the backend outliving the transaction, if it
/// leaves any. In transaction mode the client is not guaranteed the same backend
/// for its next transaction, so such state leaks to other clients.
fn statement_leak(node: &pg_query::NodeEnum) -> Option<Atom> {
    match node {
        // SET LOCAL, SET TRANSACTION and SET TRANSACTION SNAPSHOT are
        // transaction-scoped, so they are safe in transaction mode
        pg_query::NodeEnum::VariableSetStmt(stmt) => {
            let session_scoped =
                !stmt.is_local && stmt.name != "TRANSACTION" && stmt.name != "TRANSACTION SNAPSHOT";

            session_scoped.then(atoms::session_set)
        }

        // DISCARD resets backend state wholesale, including the prepared
        // statements we track for the connection
        pg_query::NodeEnum::DiscardStmt(_) => Some(atoms::discard()),

        // The notification registration outlives the transaction, but the
        // client will not get this backend back to receive on it
        pg_query::NodeEnum::ListenStmt(_) => Some(atoms::listen()),
        pg_query::NodeEnum::UnlistenStmt(_) => Some(atoms::listen()),

        // Deferred constraints are session-scoped when set outside a transaction
        pg_query::NodeEnum::ConstraintsSetStmt(_) => Some(atoms::set_constraints()),

        // The loaded module stays attached to the session
        pg_query::NodeEnum::LoadStmt(_) => Some(atoms::load()),

        // Only WITH HOLD cursors survive the commit
        pg_query::NodeEnum::DeclareCursorStmt(stmt) => {
            (stmt.options & CURSOR_OPT_HOLD != 0).then(atoms::hold_cursor)
        }

        // A temp table lives until the connection closes unless it is dropped
        // at commit
        pg_query::NodeEnum::CreateStmt(stmt) => {
            let temp = stmt
                .relation
                .as_ref()
                .is_some_and(|rel| is_temp_persistence(&rel.relpersistence))
                && stmt.oncommit != ONCOMMIT_DROP;

            temp.then(atoms::temp_table)
        }

        // CREATE TEMP TABLE ... AS SELECT, which carries its temp-ness and its
        // ON COMMIT action on the INTO clause instead
        pg_query::NodeEnum::CreateTableAsStmt(stmt) => {
            let temp = stmt.into.as_ref().is_some_and(|into| {
                into.rel
                    .as_ref()
                    .is_some_and(|rel| is_temp_persistence(&rel.relpersistence))
                    && into.on_commit != ONCOMMIT_DROP
            });

            temp.then(atoms::temp_table)
        }

        // Otherwise the statement itself is harmless, but a function call
        // anywhere inside it may not be
        _ => func_call_leak(node),
    }
}

/// `RELPERSISTENCE_TEMP` is spelled `t`. Unlogged (`u`) and permanent (`p`)
/// tables are not session state.
fn is_temp_persistence(relpersistence: &str) -> bool {
    relpersistence == "t"
}

/// Walks the node tree looking for a call to a function that mutates session
/// state. These appear inside ordinary statements — most often a bare
/// `SELECT set_config(...)` — so no statement-level match can find them.
fn func_call_leak(node: &pg_query::NodeEnum) -> Option<Atom> {
    node.nodes()
        .iter()
        .find_map(|(node_ref, _, _, _)| match node_ref {
            pg_query::NodeRef::FuncCall(func_call) => named_func_call_leak(func_call),
            _ => None,
        })
}

fn named_func_call_leak(func_call: &pg_query::protobuf::FuncCall) -> Option<Atom> {
    let name = qualified_func_name(func_call)?;

    if name == SET_CONFIG {
        // set_config(setting, value, is_local); only the session-scoped form
        // poisons the connection. A non-literal is_local (a parameter, say)
        // could be either, and flagging it would reject calls that are in fact
        // transaction-local, so it is let through
        let session_scoped = func_call
            .args
            .get(2)
            .and_then(bool_const_value)
            .is_some_and(|is_local| !is_local);

        return session_scoped.then(atoms::set_config);
    }

    SESSION_ADVISORY_LOCK_FUNCS
        .contains(&name.as_str())
        .then(atoms::advisory_lock)
}

/// The bare function name, rejecting schema qualifications other than
/// `pg_catalog` so a user-defined `myschema.set_config` is not mistaken for the
/// builtin.
fn qualified_func_name(func_call: &pg_query::protobuf::FuncCall) -> Option<String> {
    let parts: Vec<&str> = func_call
        .funcname
        .iter()
        .map(|node| match node.node.as_ref() {
            Some(pg_query::NodeEnum::String(s)) => Some(s.sval.as_str()),
            _ => None,
        })
        .collect::<Option<Vec<&str>>>()?;

    match parts.as_slice() {
        [name] => Some(name.to_string()),
        ["pg_catalog", name] => Some(name.to_string()),
        _ => None,
    }
}

/// The boolean value of a literal argument, if it is one. `TRUE`/`FALSE` parse
/// to a boolean constant, but drivers also send `'t'`/`'f'` strings and `1`/`0`.
fn bool_const_value(node: &pg_query::protobuf::Node) -> Option<bool> {
    let Some(pg_query::NodeEnum::AConst(a_const)) = node.node.as_ref() else {
        return None;
    };

    match a_const.val.as_ref()? {
        pg_query::protobuf::a_const::Val::Boolval(b) => Some(b.boolval),
        pg_query::protobuf::a_const::Val::Ival(i) => Some(i.ival != 0),
        pg_query::protobuf::a_const::Val::Sval(s) => match s.sval.to_ascii_lowercase().as_str() {
            "t" | "true" | "on" | "yes" | "1" => Some(true),
            "f" | "false" | "off" | "no" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

rustler::init!("Elixir.Supavisor.PgParser");
