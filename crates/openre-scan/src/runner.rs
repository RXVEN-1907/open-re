//! Scan runner

use crate::checks::{get_all_checks, Check};
use crate::client::{build_client, build_client_with_config};
use crate::config::ScanConfig;
use crate::output::{display_results, OutputFormat};
use anyhow::Result;
use colored::Colorize;
use openre_config::ScannerConfig;
use openre_core::result::{Finding, Severity};
use std::time::Instant;
use tracing::Level;
use url::Url;

/// Internal scan function for programmatic use
pub async fn run_scan_internal(
    target_str: String,
    profile: crate::profiles::ScanProfile,
    _format: OutputFormat,
    timeout: u64,
    max_redirects: usize,
    user_agent: String,
) -> Result<Vec<Finding>> {
    let target_url = if target_str.starts_with("http://") || target_str.starts_with("https://") {
        target_str.parse::<Url>()?
    } else {
        format!("https://{}", target_str).parse::<Url>()?
    };

    let client = build_client(timeout, max_redirects, false, user_agent, None)?;

    let all_checks = get_all_checks(&profile);
    let checks_to_run: Vec<Check> =
        all_checks.into_iter().filter(|c| c.name() != "sensitive-files").collect();

    let mut all_findings = Vec::new();

    for check in checks_to_run {
        match check.run(&client, &target_url).await {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => eprintln!("Check {} failed: {}", check.name(), e),
        }
    }

    Ok(all_findings)
}

/// Main scan function with full configuration
pub async fn run_scan(config: ScanConfig, scanner_config: &ScannerConfig) -> Result<()> {
    let target_url = config.resolve_target_url()?;

    // Use unified scanner config with CLI overrides
    let timeout = config.timeout.unwrap_or(scanner_config.timeout_secs);
    let max_redirects = config.max_redirects.unwrap_or(scanner_config.max_redirects);
    let follow_redirects = config.follow_redirects.unwrap_or(scanner_config.follow_redirects);
    let user_agent = config.user_agent.clone().unwrap_or_else(|| scanner_config.user_agent.clone());
    let headers = config.headers.clone();

    let client = build_client_with_config(
        timeout,
        max_redirects,
        follow_redirects,
        user_agent,
        headers,
        scanner_config.proxy.clone(),
        scanner_config.tls_verify,
    )?;

    let profile = config.resolve_profile(scanner_config);
    let output_format = config.resolve_format();

    let all_checks = get_all_checks(&profile);
    let checks_to_run: Vec<Check> = all_checks
        .into_iter()
        .filter(|c| {
            let should_run =
                config.checks.as_ref().map(|cs| cs.iter().any(|s| s == c.name())).unwrap_or(true);
            let should_exclude =
                config.exclude.as_ref().map(|es| es.iter().any(|s| s == c.name())).unwrap_or(false);
            should_run && !should_exclude
        })
        .collect();

    let checks_count = checks_to_run.len();

    let start_time = Instant::now();
    let mut all_findings = Vec::new();

    for check in checks_to_run.iter() {
        match check.run(&client, &target_url).await {
            Ok(findings) => {
                if !findings.is_empty() {
                    for finding in &findings {
                        println!(
                            "  {} {} {} [{}]",
                            "✓".green(),
                            finding.title.bright_white(),
                            format!("({})", finding.severity)
                                .color(severity_color(&finding.severity)),
                            check.name().dimmed()
                        );
                    }
                }
                all_findings.extend(findings);
            }
            Err(e) => {
                eprintln!(
                    "{} {} failed: {}",
                    "✗".red().bold(),
                    check.name().bright_yellow(),
                    e
                );
            }
        }
    }

    let duration = start_time.elapsed();

    display_results(
        &all_findings,
        &output_format,
        config.output,
        &target_url,
        duration,
        checks_count,
    )
    .await?;

    Ok(())
}

fn severity_color(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "red",
        Severity::High => "red",
        Severity::Medium => "yellow",
        Severity::Low => "green",
        Severity::Info => "blue",
    }
}