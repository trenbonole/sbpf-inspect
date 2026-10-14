//! WebAssembly entry point with no imports, for hosts that refuse modules declaring any (a sandbox
//! that instantiates the module with an empty import object). Built without the default
//! `bindgen` feature:
//!
//! ```sh
//! cargo build --release --target wasm32-unknown-unknown --lib --no-default-features
//! ```
//!
//! The host writes the program into memory from `sbpf_inspect_alloc(len)`, calls
//! `sbpf_inspect_run(ptr, len)`, and reads the JSON it returns as `(ptr << 32) | len`:
//! `{"ok": <report>}`, or `{"error": "<why>"}` for input that is not an sBPF program.

use std::cell::RefCell;

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// A buffer of `len` bytes for the input, valid until the next call.
#[unsafe(no_mangle)]
pub extern "C" fn sbpf_inspect_alloc(len: usize) -> *mut u8 {
    INPUT.with_borrow_mut(|b| {
        *b = vec![0; len];
        b.as_mut_ptr()
    })
}

/// Inspect the `len` bytes at `ptr` (the buffer from `sbpf_inspect_alloc`) and return where the
/// JSON result is, as `(ptr << 32) | len`, valid until the next call.
///
/// # Safety
///
/// `ptr` and `len` must describe memory the host wrote, such as the buffer `sbpf_inspect_alloc`
/// returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbpf_inspect_run(ptr: *const u8, len: usize) -> u64 {
    // SAFETY: the caller passes memory it wrote, inside this module's linear memory.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    // The report is written as it is, keeping its field order, inside the outer object.
    let json = match crate::inspect(bytes).map_err(|e| e.to_string()).and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string())) {
        Ok(report) => format!("{{\"ok\":{report}}}"),
        Err(e) => format!("{{\"error\":{}}}", serde_json::Value::String(e)),
    }
    .into_bytes();
    OUTPUT.with_borrow_mut(|out| {
        *out = json;
        ((out.as_ptr() as u64) << 32) | out.len() as u64
    })
}
