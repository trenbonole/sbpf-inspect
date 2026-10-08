//! WebAssembly entry point: bytes in, the JSON report out.

use wasm_bindgen::prelude::*;

/// Inspect one sBPF program ELF and return the report as a JSON string.
#[wasm_bindgen(js_name = inspect)]
pub fn inspect_json(bytes: &[u8]) -> Result<String, JsError> {
    let report = crate::inspect(bytes).map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))
}

/// Engine name and version, for provenance.
#[wasm_bindgen(js_name = engineVersion)]
pub fn engine_version() -> String {
    format!("{} {}", crate::ENGINE_NAME, crate::ENGINE_VERSION)
}
