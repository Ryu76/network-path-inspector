// Supervisor-owned adapter: exercises the real npi-core public API, never a substitute engine.
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, BufRead};
fn answer(input: &Value) -> Value {
    let null = Value::Null;
    let value = input.get("value").unwrap_or(&null);
    let validation = match input["op"].as_str().unwrap_or("") {
        "validate_profile" => Some(npi_core::validate_profile(value)),
        "validate_session" => Some(npi_core::validate_session(value)),
        "validate_registry" => Some(npi_core::validate_registry(value)),
        _ => None,
    };
    if let Some(result) = validation {
        return match result { Ok(()) => json!({"ok":true}), Err(errors) => json!({"ok":false,"errors":errors}) };
    }
    match input["op"].as_str().unwrap_or("") {
        "registry" => npi_core::canonical_registry(),
        "classify" => json!(npi_core::classify_tcp_error(input["code"].as_i64().and_then(|v|i32::try_from(v).ok()),input["timed_out"].as_bool().unwrap_or(false),input["cancelled"].as_bool().unwrap_or(false))),
        "plan" | "restore" => {
            let registry = input.get("registry").cloned().unwrap_or_else(npi_core::canonical_registry);
            let caps: BTreeSet<String> = input["capabilities"].as_array().map(|a|a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
            let result = if input["op"] == "plan" { npi_core::plan_features(value,&registry,&caps) } else { npi_core::restore_profile(value,&registry) };
            match result { Ok(result)=>json!({"ok":true,"result":result}),Err(errors)=>json!({"ok":false,"errors":errors}) }
        },
        "convert" => match npi_core::convert_legacy_session(value) { Ok(result)=>json!({"ok":true,"result":result}),Err(errors)=>json!({"ok":false,"errors":errors}) },
        _ => json!({"ok":false,"error":"unknown supervisor probe operation"}),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = match line { Ok(text)=>match serde_json::from_str::<Value>(&text) {Ok(input)=>answer(&input),Err(error)=>json!({"parse_error":error.to_string()})},Err(error)=>json!({"io_error":error.to_string()})};
        println!("{result}");
    }
}
