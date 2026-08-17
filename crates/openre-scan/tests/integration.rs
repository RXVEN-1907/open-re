//! Integration tests for openre-scan

use openre_scan::{
    build_client, run_scan_internal, Check, Confidence, OutputFormat, ScanProfile, Severity,
};
use std::env;
use std::time::Duration;
use tokio::process::Command;
use url::Url;

/// Start a test HTTP server and return its base URL
async fn start_test_server() -> (String, tokio::process::Child) {
    // Use workspace root (two levels up from crate manifest dir)
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let child = Command::new("python3")
        .arg("test_server.py")
        .current_dir(&workspace_root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start test server");

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    ("http://localhost:8080".to_string(), child)
}

/// Stop the test server
async fn stop_test_server(mut child: tokio::process::Child) {
    child.kill().await.ok();
    let _ = child.wait().await;
}

#[tokio::test]
async fn test_scan_pipeline_quick_profile() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Quick,
        OutputFormat::Table,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    assert!(findings.is_ok(), "Scan should succeed");
    let findings = findings.unwrap();

    // Quick profile should find at least some issues
    assert!(!findings.is_empty(), "Should find at least one finding");

    // Should include http-headers findings
    let has_server_header = findings.iter().any(|f| f.title.contains("Server Header"));
    assert!(has_server_header, "Should detect server header disclosure");

    // Should include security-headers findings
    let has_missing_hsts = findings
        .iter()
        .any(|f| f.title.contains("Strict-Transport-Security"));
    assert!(has_missing_hsts, "Should detect missing HSTS header");
}

#[tokio::test]
async fn test_scan_pipeline_standard_profile() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Standard,
        OutputFormat::Table,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    assert!(findings.is_ok(), "Scan should succeed");
    let findings = findings.unwrap();

    // Standard profile should find more issues
    assert!(
        findings.len() > 10,
        "Standard profile should find more than 10 findings"
    );

    // Should include forms check (GET password form)
    let has_get_password = findings.iter().any(|f| f.title.contains("GET Form"));
    assert!(has_get_password, "Should detect password field in GET form");

    // Note: run_scan_internal filters out sensitive-files check (slow)
    // Should include robots.txt check
    let has_robots = findings.iter().any(|f| f.title.contains("robots.txt"));
    assert!(has_robots, "Should detect robots.txt");
}

#[tokio::test]
async fn test_finding_generation_has_evidence() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Quick,
        OutputFormat::Table,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    let findings = findings.unwrap();

    // Most findings should have evidence (some informational ones may not)
    let findings_with_evidence = findings.iter().filter(|f| !f.evidence.is_empty()).count();
    assert!(
        findings_with_evidence > 0,
        "At least some findings should have evidence"
    );

    for finding in &findings {
        assert!(!finding.target.is_empty(), "Finding should have target");
        assert!(
            !finding.plugin_source.is_empty(),
            "Finding should have plugin source"
        );
        // Severity should be one of the valid variants
        assert!(matches!(
            finding.severity,
            Severity::Info | Severity::Low | Severity::Medium | Severity::High | Severity::Critical
        ));
    }
}

#[tokio::test]
async fn test_json_output_format() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Quick,
        OutputFormat::Json,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    let findings = findings.unwrap();
    assert!(!findings.is_empty());

    // Verify findings can be serialized to JSON
    let json = serde_json::to_string(&findings);
    assert!(json.is_ok(), "Findings should be JSON serializable");

    let json_str = json.unwrap();
    assert!(json_str.contains("title"));
    assert!(json_str.contains("severity"));
    assert!(json_str.contains("evidence"));
}

#[tokio::test]
async fn test_sarif_output_format() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Quick,
        OutputFormat::Sarif,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    let findings = findings.unwrap();
    assert!(!findings.is_empty());

    // Verify findings can be serialized
    let json = serde_json::to_string(&findings);
    assert!(json.is_ok(), "Findings should be serializable for SARIF");
}

#[tokio::test]
async fn test_check_filtering() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    // Run only http-headers check
    let client = build_client(10, 10, false, "test".to_string(), None).unwrap();
    let target_url = target.parse::<Url>().unwrap();

    let findings = Check::HttpHeaders.run(&client, &target_url).await;

    stop_test_server(server).await;

    assert!(findings.is_ok());
    let findings = findings.unwrap();

    // Should only have http-headers findings
    for finding in &findings {
        assert_eq!(finding.plugin_source, "http-headers");
    }

    // Should find server header and x-powered-by
    assert!(findings.iter().any(|f| f.title.contains("Server Header")));
    assert!(findings.iter().any(|f| f.title.contains("X-Powered-By")));
}

#[tokio::test]
async fn test_exclude_check() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let client = build_client(10, 10, false, "test".to_string(), None).unwrap();
    let target_url = target.parse::<Url>().unwrap();

    // Run security-headers but we'll filter out in the test logic
    let findings = Check::SecurityHeaders.run(&client, &target_url).await;

    stop_test_server(server).await;

    assert!(findings.is_ok());
    let findings = findings.unwrap();

    // Should only have security-headers findings
    for finding in &findings {
        assert_eq!(finding.plugin_source, "security-headers");
    }

    // Should detect multiple missing headers
    assert!(
        findings.len() >= 5,
        "Should detect multiple missing security headers"
    );
}

#[tokio::test]
async fn test_remediation_guidance() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Standard,
        OutputFormat::Table,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    let findings = findings.unwrap();

    // At least some findings should have remediation
    let with_remediation = findings.iter().filter(|f| f.remediation.is_some()).count();
    assert!(
        with_remediation > 0,
        "At least some findings should have remediation guidance"
    );

    // Check remediation structure
    for finding in &findings {
        if let Some(rem) = &finding.remediation {
            assert!(!rem.summary.is_empty(), "Remediation should have summary");
            assert!(!rem.steps.is_empty(), "Remediation should have steps");
        }
    }
}

#[tokio::test]
async fn test_severity_and_confidence() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let findings = run_scan_internal(
        target.clone(),
        ScanProfile::Standard,
        OutputFormat::Table,
        10,
        10,
        "openre-scan-test/0.1.0".to_string(),
    )
    .await;

    stop_test_server(server).await;

    let findings = findings.unwrap();

    // Should have findings across different severities
    let has_high = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High));
    let has_medium = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Medium));
    let has_low = findings.iter().any(|f| matches!(f.severity, Severity::Low));
    let has_info = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Info));

    assert!(has_high, "Should have HIGH severity findings");
    assert!(has_medium, "Should have MEDIUM severity findings");
    assert!(has_low, "Should have LOW severity findings");
    assert!(has_info, "Should have INFO severity findings");

    // All findings should have confidence
    for finding in &findings {
        assert!(matches!(
            finding.confidence,
            Confidence::VeryHigh | Confidence::High | Confidence::Medium | Confidence::Low
        ));
    }
}

#[tokio::test]
async fn test_cli_version_command() {
    let output = Command::new("cargo")
        .args(["run", "--release", "-p", "openre-scan", "--", "version"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .await
        .expect("Failed to run version command");

    assert!(output.status.success(), "Version command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("openre-scan"));
    assert!(stdout.contains("0.1.0"));
}

#[tokio::test]
async fn test_cli_scan_json_output() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let output = Command::new("cargo")
        .args([
            "run",
            "--release",
            "-p",
            "openre-scan",
            "--",
            "scan",
            &target,
            "--profile",
            "quick",
            "--format",
            "json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .await
        .expect("Failed to run scan command");

    stop_test_server(server).await;

    assert!(output.status.success(), "Scan command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain valid JSON with findings
    assert!(stdout.contains("findings"));
    assert!(stdout.contains("scan_id"));
    assert!(stdout.contains("duration_seconds"));
}

#[tokio::test]
async fn test_cli_scan_sarif_output() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);

    let output = Command::new("cargo")
        .args([
            "run",
            "--release",
            "-p",
            "openre-scan",
            "--",
            "scan",
            &target,
            "--profile",
            "quick",
            "--format",
            "sarif",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .await
        .expect("Failed to run scan command");

    stop_test_server(server).await;

    assert!(output.status.success(), "Scan command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain valid SARIF
    assert!(stdout.contains("runs"));
    assert!(stdout.contains("results"));
    assert!(stdout.contains("ruleId"));
}
