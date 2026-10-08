//! `sbpf-inspect <program.so> [--compact]`: print the JSON report for one program.

use std::{fs, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let compact = args.iter().any(|a| a == "--compact");
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: sbpf-inspect <program.so> [--compact]");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match sbpf_inspect::inspect(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let json = if compact { serde_json::to_string(&report) } else { serde_json::to_string_pretty(&report) };
    match json {
        Ok(j) => {
            println!("{j}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("cannot serialize report: {e}");
            ExitCode::from(1)
        }
    }
}
