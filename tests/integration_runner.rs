//! Integration test runner
//!
//! This simply invokes the shell-based integration tests.
//! Run with: cargo test --test integration

use std::process::Command;

fn main() {
    let status = Command::new("bash")
        .arg("tests/integration.sh")
        .status()
        .expect("Failed to run integration tests");

    if !status.success() {
        std::process::exit(1);
    }
}
