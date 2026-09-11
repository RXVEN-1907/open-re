//! Version information

use colored::Colorize;

/// Print version information
pub fn show_version() {
    println!("{} {}", "Version:".bold(), env!("CARGO_PKG_VERSION").bright_white());
    println!("{} {}", "Component:".bold(), "openre-scan (standalone scanner)".bright_white());
    println!(
        "{} {}",
        "Repository:".bold(),
        "https://github.com/RXVEN-1907/open-re".bright_blue().underline()
    );
    println!("{} {}", "Platform:".bold(), "open-re v0.2.0-dev".bright_white());
    println!();
    println!("{}", "Part of the open-re platform:".dimmed());
    println!("  • openre-scan — Standalone security scanner (this tool)");
    println!("  • openre-cli — Unified CLI for all platform operations");
    println!("  • openre-api — REST/gRPC API server");
    println!("  • openre-analysis — Binary analysis pipeline");
    println!("  • openre-plugins — WASM plugin system");
    println!("  • openre-security-ai — AI-powered vulnerability analysis");
}
