//! Dependency Analysis - Analyze package manager lockfiles and manifests

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

/// Configuration for dependency analysis
#[derive(Debug, Clone)]
pub struct DependencyAnalysisConfig {
    /// Enable caching of dependency data
    pub enable_caching: bool,

    /// Cache TTL in seconds (default: 1 day)
    pub cache_ttl_seconds: u64,

    /// Whether to check for known vulnerabilities
    pub check_vulnerabilities: bool,

    /// Whether to check for outdated dependencies
    pub check_outdated: bool,
}

impl Default for DependencyAnalysisConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl_seconds: 86400, // 1 day
            check_vulnerabilities: true,
            check_outdated: true,
        }
    }
}

/// Dependency analyzer for various package ecosystems
pub struct DependencyAnalyzer {
    config: DependencyAnalysisConfig,
    vulnerability_db: Option<std::sync::RwLock<VulnerabilityDatabase>>,
    registry_clients: HashMap<String, Box<dyn RegistryClient>>,
}

/// Trait for registry clients (npm, crates.io, pypi, etc.)
#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync {
    /// Get latest version of a package
    async fn get_latest_version(&self, package_name: &str) -> IntelligenceResult<Option<String>>;

    /// Get all versions of a package
    async fn get_versions(&self, package_name: &str) -> IntelligenceResult<Vec<String>>;

    /// Get known vulnerabilities for a package version
    async fn get_vulnerabilities(
        &self,
        package_name: &str,
        version: &str,
    ) -> IntelligenceResult<Vec<DependencyVulnerability>>;

    /// Get registry name for logging/debugging
    fn registry_name(&self) -> &str;
}

/// In-memory vulnerability database
#[derive(Debug)]
struct VulnerabilityDatabase {
    entries: HashMap<String, Vec<DependencyVulnerability>>,
    cached_at: std::time::SystemTime,
    ttl_seconds: u64,
}

impl VulnerabilityDatabase {
    fn new(ttl_seconds: u64) -> Self {
        Self {
            entries: HashMap::new(),
            cached_at: std::time::SystemTime::now(),
            ttl_seconds,
        }
    }

    fn is_valid(&self) -> bool {
        if let Ok(elapsed) = self.cached_at.elapsed() {
            elapsed.as_secs() < self.ttl_seconds
        } else {
            false
        }
    }

    fn get_vulnerabilities(&self, package_key: &str) -> Option<&Vec<DependencyVulnerability>> {
        if self.is_valid() {
            self.entries.get(package_key)
        } else {
            None
        }
    }

    fn add_vulnerabilities(
        &mut self,
        package_key: String,
        vulnerabilities: Vec<DependencyVulnerability>,
    ) {
        self.entries.insert(package_key, vulnerabilities);
    }
}

/// Supported dependency file types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyFileType {
    /// package-lock.json (npm)
    NpmLock,

    /// yarn.lock (Yarn)
    YarnLock,

    /// Cargo.lock (Rust)
    CargoLock,

    /// requirements.txt (Python)
    PythonRequirements,

    /// Pipfile.lock (Pipenv)
    PipfileLock,

    /// go.mod/go.sum (Go)
    GoMod,

    /// package.json (Node.js - less precise)
    PackageJson,

    /// pom.xml (Maven)
    MavenPom,

    /// build.gradle (Gradle)
    GradleBuild,
}

impl DependencyFileType {
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_lowercase().as_str() {
            "json" => Some(DependencyFileType::NpmLock), // Default to npm lock
            "lock" => Some(DependencyFileType::CargoLock), // Default to Cargo
            "txt" => Some(DependencyFileType::PythonRequirements),
            "mod" => Some(DependencyFileType::GoMod),
            "xml" => Some(DependencyFileType::MavenPom),
            _ => None,
        }
    }

    pub fn from_filename(filename: &str) -> Option<Self> {
        match filename.to_lowercase().as_str() {
            "package-lock.json" => Some(DependencyFileType::NpmLock),
            "yarn.lock" => Some(DependencyFileType::YarnLock),
            "cargo.lock" => Some(DependencyFileType::CargoLock),
            "requirements.txt" => Some(DependencyFileType::PythonRequirements),
            "pipfile.lock" => Some(DependencyFileType::PipfileLock),
            "go.mod" => Some(DependencyFileType::GoMod),
            "package.json" => Some(DependencyFileType::PackageJson),
            "pom.xml" => Some(DependencyFileType::MavenPom),
            "build.gradle" => Some(DependencyFileType::GradleBuild),
            _ => None,
        }
    }

    /// Best-effort detection based on file contents (used when the name or
    /// extension is unrecognizable, e.g. temp files)
    pub fn from_content(content: &str) -> Option<Self> {
        let trimmed = content.trim_start();
        if trimmed.starts_with('{') && content.contains("\"dependencies\"") {
            return Some(DependencyFileType::PackageJson);
        }
        if trimmed.starts_with('{') && content.contains("created-by pip") {
            return Some(DependencyFileType::PipfileLock);
        }
        if content.contains("[[package]]") {
            return Some(DependencyFileType::CargoLock);
        }
        // requirements.txt style: `name==version` / `name>=version` lines
        let looks_like_requirements = content.lines().any(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                return false;
            }
            // Strip inline comments and environment markers
            let spec = line.split('#').next().unwrap_or(line).trim();
            let spec = spec.split(';').next().unwrap_or(spec).trim();
            let name = spec
                .split(|c: char| c == '=' || c == '>' || c == '<' || c == '!' || c == '~')
                .next()
                .unwrap_or("");
            !name.trim().is_empty()
                && name.chars().all(|c| {
                    c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '[' || c == ']'
                })
                && spec.len() > name.len()
        });
        if looks_like_requirements {
            return Some(DependencyFileType::PythonRequirements);
        }
        if content.contains("<project") && content.contains("<dependency>") {
            return Some(DependencyFileType::MavenPom);
        }
        if content.contains("apply plugin:") || content.contains("implementation ") {
            return Some(DependencyFileType::GradleBuild);
        }
        if content.contains("require (") || (content.contains("module ") && content.contains("go "))
        {
            return Some(DependencyFileType::GoMod);
        }
        None
    }
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer
    pub fn new(config: DependencyAnalysisConfig) -> Self {
        let vulnerability_db = if config.check_vulnerabilities && config.enable_caching {
            Some(std::sync::RwLock::new(VulnerabilityDatabase::new(
                config.cache_ttl_seconds,
            )))
        } else {
            None
        };

        Self {
            vulnerability_db,
            registry_clients: HashMap::new(),
            config,
        }
    }

    /// Add a registry client for an ecosystem
    pub fn add_registry_client(&mut self, ecosystem: &str, client: Box<dyn RegistryClient>) {
        self.registry_clients.insert(ecosystem.to_string(), client);
    }

    /// Number of registered registry clients
    pub fn registry_client_count(&self) -> usize {
        self.registry_clients.len()
    }

    /// Analyze dependencies from a lockfile or manifest file
    pub async fn analyze_dependencies_file<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> IntelligenceResult<Vec<DependencyInfo>> {
        let path = file_path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            IntelligenceError::Parse(format!("Failed to read dependency file: {}", e))
        })?;

        self.analyze_dependencies_content(&content, path).await
    }

    /// Analyze dependencies from content string
    pub async fn analyze_dependencies_content(
        &self,
        content: &str,
        source_path: &Path,
    ) -> IntelligenceResult<Vec<DependencyInfo>> {
        let filename = source_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown");

        let file_type = DependencyFileType::from_filename(filename)
            .or_else(|| {
                source_path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .and_then(DependencyFileType::from_extension)
            })
            .or_else(|| DependencyFileType::from_content(content))
            .ok_or_else(|| {
                IntelligenceError::InvalidInput(format!(
                    "Unsupported dependency file type: {}",
                    filename
                ))
            })?;

        match file_type {
            DependencyFileType::NpmLock => self.parse_npm_lock(content).await,
            DependencyFileType::YarnLock => self.parse_yarn_lock(content).await,
            DependencyFileType::CargoLock => self.parse_cargo_lock(content).await,
            DependencyFileType::PythonRequirements => self.parse_python_requirements(content).await,
            DependencyFileType::PipfileLock => self.parse_pipfile_lock(content).await,
            DependencyFileType::GoMod => self.parse_go_mod(content).await,
            DependencyFileType::PackageJson => self.parse_package_json(content).await,
            DependencyFileType::MavenPom => self.parse_maven_pom(content).await,
            DependencyFileType::GradleBuild => self.parse_gradle_build(content).await,
        }
    }

    /// Parse npm package-lock.json
    async fn parse_npm_lock(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        #[derive(Deserialize)]
        struct PackageLock {
            #[serde(default)]
            dependencies: HashMap<String, PackageInfo>,
            #[serde(rename = "lockfileVersion")]
            lockfile_version: Option<u32>,
        }

        #[derive(Deserialize)]
        struct PackageInfo {
            version: String,
            #[serde(default)]
            dependencies: HashMap<String, PackageInfo>,
        }

        let lock_file: PackageLock = serde_json::from_str(content)
            .map_err(|e| IntelligenceError::Parse(format!("Invalid package-lock.json: {}", e)))?;

        let mut dependencies = Vec::new();

        for (name, info) in &lock_file.dependencies {
            let dep_info = self
                .analyze_single_dependency(name, &info.version, "npm")
                .await?;
            dependencies.push(dep_info);
        }

        Ok(dependencies)
    }

    /// Parse Cargo.lock (Rust)
    async fn parse_cargo_lock(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        // Simple parsing approach - in reality would use toml crate
        let mut dependencies = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        let mut in_package_section = false;

        for line in lines {
            let trimmed = line.trim();

            if trimmed == "[[package]]" {
                in_package_section = true;
                continue;
            }

            if in_package_section {
                if trimmed.starts_with('[') {
                    in_package_section = false;
                    continue;
                }

                if trimmed.starts_with("name = ") {
                    let name = trimmed[8..trimmed.len() - 1].to_string(); // Extract quoted string
                                                                          // Would need to find the version line in the same package section
                                                                          // This is simplified for demonstration
                }
            }
        }

        // For now, return empty - would implement full parsing in production
        Ok(dependencies)
    }

    /// Parse Python requirements.txt
    async fn parse_python_requirements(
        &self,
        content: &str,
    ) -> IntelligenceResult<Vec<DependencyInfo>> {
        let mut dependencies = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse package==version format
            if let Some(eq_pos) = trimmed.find("==") {
                let name = &trimmed[..eq_pos];
                let version = &trimmed[eq_pos + 2..];

                let dep_info = self
                    .analyze_single_dependency(name, version, "pypi")
                    .await?;
                dependencies.push(dep_info);
            }
        }

        Ok(dependencies)
    }

    /// Parse yarn.lock
    async fn parse_yarn_lock(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        let mut dependencies = Vec::new();
        let mut current_name: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Entry header: "package@^1.2.3", package@^1.2.3:
            if !trimmed.starts_with("version") && !trimmed.starts_with("dependencies") {
                if trimmed.contains('@') && trimmed.ends_with(':') {
                    // Strip quotes and trailing colon, then take the package name (before last @version spec)
                    let entry = trimmed.trim_end_matches(':').trim_matches('"');
                    if let Some(pos) = entry.rfind('@') {
                        if pos > 0 {
                            current_name = Some(entry[..pos].to_string());
                        }
                    }
                    continue;
                }
            }

            // Version line: version "1.2.3"
            if trimmed.starts_with("version ") && trimmed.contains('"') {
                if let Some(name) = &current_name {
                    let version = trimmed.split('"').nth(1).unwrap_or_default().to_string();
                    dependencies.push(
                        self.analyze_single_dependency(name, &version, "npm")
                            .await?,
                    );
                    current_name = None;
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse Pipfile.lock (Pipenv)
    async fn parse_pipfile_lock(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        #[derive(Deserialize)]
        struct PipfileLock {
            #[serde(default)]
            default: HashMap<String, PipPackageInfo>,
            #[serde(default)]
            develop: HashMap<String, PipPackageInfo>,
        }

        #[derive(Deserialize)]
        struct PipPackageInfo {
            #[serde(default)]
            version: String,
        }

        let lock_file: PipfileLock = serde_json::from_str(content)
            .map_err(|e| IntelligenceError::Parse(format!("Invalid Pipfile.lock: {}", e)))?;

        let mut dependencies = Vec::new();
        let mut packages = Vec::new();
        packages.extend(lock_file.default);
        packages.extend(lock_file.develop);

        for (name, info) in packages {
            // Version is stored as "==1.2.3"
            let version = info
                .version
                .trim_start_matches(['=', '<', '>', '~'])
                .to_string();
            dependencies.push(
                self.analyze_single_dependency(&name, &version, "pypi")
                    .await?,
            );
        }

        Ok(dependencies)
    }

    /// Parse go.mod
    async fn parse_go_mod(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        let mut dependencies = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // require github.com/foo/bar v1.2.3
            if let Some(rest) = trimmed.strip_prefix("require ") {
                let rest = rest.trim();
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    let version = parts[1].trim_start_matches('v');
                    dependencies.push(self.analyze_single_dependency(name, version, "go").await?);
                }
            } else if trimmed == "require (" {
                continue;
            } else if trimmed.ends_with(')') && !trimmed.contains(' ') {
                continue;
            }
        }

        Ok(dependencies)
    }

    /// Parse package.json
    async fn parse_package_json(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        #[derive(Deserialize)]
        struct PackageJson {
            #[serde(default)]
            dependencies: HashMap<String, String>,
            #[serde(default)]
            devDependencies: HashMap<String, String>,
        }

        let package_json: PackageJson = serde_json::from_str(content)
            .map_err(|e| IntelligenceError::Parse(format!("Invalid package.json: {}", e)))?;

        let mut dependencies = Vec::new();
        let mut all_deps = Vec::new();
        all_deps.extend(package_json.dependencies);
        all_deps.extend(package_json.devDependencies);

        for (name, version_spec) in all_deps {
            // Version specs may be ranges like "^4.18.2" or "~2.0.1"
            let version = version_spec
                .trim_start_matches(['^', '~', '>', '=', '<', 'v', ' '])
                .to_string();
            dependencies.push(
                self.analyze_single_dependency(&name, &version, "npm")
                    .await?,
            );
        }

        Ok(dependencies)
    }

    /// Parse Maven pom.xml
    async fn parse_maven_pom(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        let mut dependencies = Vec::new();

        // Simple block-based parsing of <dependency>...</dependency> sections
        for block in content.split("<dependency>").skip(1) {
            if let Some(end) = block.find("</dependency>") {
                let block = &block[..end];

                let extract_tag = |tag: &str, text: &str| -> Option<String> {
                    let open = format!("<{}>", tag);
                    let close = format!("</{}>", tag);
                    let start_idx = text.find(&open)? + open.len();
                    let end_idx = text[start_idx..].find(&close)? + start_idx;
                    Some(text[start_idx..end_idx].trim().to_string())
                };

                let group_id = extract_tag("groupId", block);
                let artifact_id = extract_tag("artifactId", block);
                let version = extract_tag("version", block);

                if let (Some(group_id), Some(artifact_id)) = (group_id, artifact_id) {
                    let name = format!("{}:{}", group_id, artifact_id);
                    if let Some(version) = version {
                        dependencies.push(
                            self.analyze_single_dependency(&name, &version, "maven")
                                .await?,
                        );
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse build.gradle
    async fn parse_gradle_build(&self, content: &str) -> IntelligenceResult<Vec<DependencyInfo>> {
        let mut dependencies = Vec::new();

        // Match lines like: implementation 'group:name:version'
        // or implementation group: 'g', name: 'n', version: 'v'
        let single_line_re = regex::Regex::new(
            r#"(?:implementation|api|compile|runtimeOnly|testImplementation)\s+[\'"]([^:\'\"]+):([^:\'\"]+):([^:\'\"]+)[\'"]"#,
        )
        .unwrap();
        let map_line_re = regex::Regex::new(
            r#"group:\s*[\'"]([^\'"]+)[\'"],\s*name:\s*[\'"]([^\'"]+)[\'"],\s*version:\s*[\'"]([^\'"]+)[\'"]"#,
        )
        .unwrap();

        for line in content.lines() {
            let trimmed = line.trim();

            let mut matched = false;
            for caps in single_line_re.captures_iter(trimmed) {
                let name = format!("{}:{}", &caps[1], &caps[2]);
                let version = caps[3].to_string();
                dependencies.push(
                    self.analyze_single_dependency(&name, &version, "maven")
                        .await?,
                );
                matched = true;
            }

            if !matched {
                for caps in map_line_re.captures_iter(trimmed) {
                    let name = format!("{}:{}", &caps[1], &caps[2]);
                    let version = caps[3].to_string();
                    dependencies.push(
                        self.analyze_single_dependency(&name, &version, "maven")
                            .await?,
                    );
                }
            }
        }

        Ok(dependencies)
    }

    /// Analyze a single dependency
    async fn analyze_single_dependency(
        &self,
        name: &str,
        version: &str,
        ecosystem: &str,
    ) -> IntelligenceResult<DependencyInfo> {
        let mut dep_info = DependencyInfo {
            name: name.to_string(),
            version: version.to_string(),
            latest_version: None,
            is_outdated: false,
            vulnerabilities: Vec::new(),
            upgrade_recommendation: None,
            ecosystem: ecosystem.to_string(),
        };

        // Check for outdated dependencies
        if self.config.check_outdated {
            if let Some(client) = self.registry_clients.get(ecosystem) {
                match client.get_latest_version(name).await {
                    Ok(Some(latest)) => {
                        dep_info.latest_version = Some(latest.clone());

                        // Compare versions using semver
                        if let (Ok(current_ver), Ok(latest_ver)) =
                            (Version::parse(version), Version::parse(&latest))
                        {
                            if current_ver < latest_ver {
                                dep_info.is_outdated = true;
                            }
                        }
                    }
                    Ok(None) => {
                        warn!(
                            "Package {} not found in {} registry",
                            name,
                            client.registry_name()
                        );
                    }
                    Err(e) => {
                        warn!("Error checking latest version for {}: {}", name, e);
                    }
                }
            }
        }

        // Check for vulnerabilities
        if self.config.check_vulnerabilities {
            let vuln_key = format!("{}:{}:{}", ecosystem, name, version);

            // Check cache first
            let cached_vulns = if let Some(db) = &self.vulnerability_db {
                db.read().unwrap().get_vulnerabilities(&vuln_key).cloned()
            } else {
                None
            };

            let vulnerabilities = if let Some(cached) = cached_vulns {
                cached
            } else {
                // Check registry for vulnerabilities
                let mut vulns = Vec::new();

                if let Some(client) = self.registry_clients.get(ecosystem) {
                    match client.get_vulnerabilities(name, version).await {
                        Ok(v) => vulns = v,
                        Err(e) => {
                            warn!(
                                "Error checking vulnerabilities for {} {}: {}",
                                name, version, e
                            );
                        }
                    }
                }

                // Cache the results
                if let Some(db) = &self.vulnerability_db {
                    db.write()
                        .unwrap()
                        .add_vulnerabilities(vuln_key, vulns.clone());
                }

                vulns
            };

            dep_info.vulnerabilities = vulnerabilities;

            // Generate upgrade recommendation if there are critical vulnerabilities
            if !dep_info.vulnerabilities.is_empty() {
                let highest_severity = dep_info
                    .vulnerabilities
                    .iter()
                    .map(|v| v.severity.value())
                    .max()
                    .unwrap_or(0);

                let risk_level = match highest_severity {
                    4 => DependencyUpgradeRisk::Critical, // Critical
                    3 => DependencyUpgradeRisk::High,     // High
                    2 => DependencyUpgradeRisk::Medium,   // Medium
                    1 => DependencyUpgradeRisk::Low,      // Low
                    _ => DependencyUpgradeRisk::Low,
                };

                dep_info.upgrade_recommendation = Some(UpgradeRecommendation {
                    target_version: dep_info
                        .latest_version
                        .clone()
                        .unwrap_or_else(|| "latest".to_string()),
                    risk_level,
                    fixes_description: format!(
                        "Fixes {} known vulnerabilities",
                        dep_info.vulnerabilities.len()
                    ),
                });
            }
        }

        Ok(dep_info)
    }

    /// Generate a dependency analysis report
    pub fn generate_analysis_report(&self, dependencies: &[DependencyInfo]) -> String {
        let mut report = String::new();
        report.push_str("# Dependency Analysis Report\n\n");

        let total_deps = dependencies.len();
        let outdated_deps = dependencies.iter().filter(|d| d.is_outdated).count();
        let vulnerable_deps = dependencies
            .iter()
            .filter(|d| !d.vulnerabilities.is_empty())
            .count();

        report.push_str(&format!("## Summary\n"));
        report.push_str(&format!("- Total dependencies: {}\n", total_deps));
        report.push_str(&format!(
            "- Outdated dependencies: {} ({:.1}%)\n",
            outdated_deps,
            if total_deps > 0 {
                (outdated_deps as f64 / total_deps as f64) * 100.0
            } else {
                0.0
            }
        ));
        report.push_str(&format!(
            "- Vulnerable dependencies: {} ({:.1}%)\n\n",
            vulnerable_deps,
            if total_deps > 0 {
                (vulnerable_deps as f64 / total_deps as f64) * 100.0
            } else {
                0.0
            }
        ));

        if vulnerable_deps > 0 {
            report.push_str("## Vulnerabilities Found\n\n");

            for dep in dependencies
                .iter()
                .filter(|d| !d.vulnerabilities.is_empty())
            {
                report.push_str(&format!("### {} v{}\n", dep.name, dep.version));

                for vuln in &dep.vulnerabilities {
                    let severity_str = match vuln.severity {
                        openre_core::result::Severity::Critical => "CRITICAL",
                        openre_core::result::Severity::High => "HIGH",
                        openre_core::result::Severity::Medium => "MEDIUM",
                        openre_core::result::Severity::Low => "LOW",
                        openre_core::result::Severity::Info => "INFO",
                    };

                    report.push_str(&format!(
                        "- **{}** [{}] {}\n",
                        vuln.id, severity_str, vuln.description
                    ));
                }

                if let Some(recommendation) = &dep.upgrade_recommendation {
                    report.push_str(&format!(
                        "  - Recommendation: Upgrade to {} ({:?} risk)\n",
                        recommendation.target_version, recommendation.risk_level
                    ));
                }

                report.push('\n');
            }
        }

        if outdated_deps > 0 {
            report.push_str("## Outdated Dependencies\n\n");

            for dep in dependencies.iter().filter(|d| d.is_outdated) {
                report.push_str(&format!(
                    "- {} v{} (latest: {})\n",
                    dep.name,
                    dep.version,
                    dep.latest_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                ));
            }
        }

        report
    }
}

/// Mock registry client for testing
#[derive(Debug)]
pub struct MockRegistryClient {
    registry_name: String,
    package_data: HashMap<String, (String, Vec<DependencyVulnerability>)>,
}

impl MockRegistryClient {
    pub fn new(registry_name: &str) -> Self {
        let mut client = Self {
            registry_name: registry_name.to_string(),
            package_data: HashMap::new(),
        };

        // Add some test data
        client.package_data.insert(
            "express".to_string(),
            (
                "4.18.2".to_string(), // latest version
                vec![DependencyVulnerability {
                    id: "CVE-2023-XXXX".to_string(),
                    severity: openre_core::result::Severity::High,
                    description: "Prototype pollution vulnerability in Express.js".to_string(),
                    cvss_score: Some(7.5),
                    affected_ranges: vec![VersionRange {
                        start_version: Some("4.0.0".to_string()),
                        end_version: Some("4.18.1".to_string()),
                        is_vulnerable: true,
                    }],
                    fixed_in: vec!["4.18.2".to_string()],
                }],
            ),
        );

        client
    }
}

#[async_trait::async_trait]
impl RegistryClient for MockRegistryClient {
    fn registry_name(&self) -> &str {
        &self.registry_name
    }

    async fn get_latest_version(&self, package_name: &str) -> IntelligenceResult<Option<String>> {
        if let Some((latest, _)) = self.package_data.get(package_name) {
            Ok(Some(latest.clone()))
        } else {
            Ok(None)
        }
    }

    async fn get_versions(&self, _package_name: &str) -> IntelligenceResult<Vec<String>> {
        // Simplified implementation
        Ok(vec![
            "1.0.0".to_string(),
            "1.1.0".to_string(),
            "2.0.0".to_string(),
        ])
    }

    async fn get_vulnerabilities(
        &self,
        package_name: &str,
        version: &str,
    ) -> IntelligenceResult<Vec<DependencyVulnerability>> {
        if let Some((latest_version, vulnerabilities)) = self.package_data.get(package_name) {
            // Check if the version is vulnerable
            let mut applicable_vulns = Vec::new();

            for vuln in vulnerabilities {
                for range in &vuln.affected_ranges {
                    if let (Some(start), Some(end)) = (&range.start_version, &range.end_version) {
                        if let (Ok(ver), Ok(start_ver), Ok(end_ver)) = (
                            Version::parse(version),
                            Version::parse(start),
                            Version::parse(end),
                        ) {
                            if ver >= start_ver && ver < end_ver {
                                applicable_vulns.push(vuln.clone());
                                break;
                            }
                        }
                    }
                }
            }

            Ok(applicable_vulns)
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_python_requirements_parsing() {
        let content = r#"
# Development dependencies
flask==2.0.1
requests==2.25.1
# Production dependencies
django==3.2.0  # Old version with known vulnerabilities
numpy>=1.20.0
        "#;

        let mut analyzer = DependencyAnalyzer::new(DependencyAnalysisConfig::default());
        analyzer.add_registry_client("pypi", Box::new(MockRegistryClient::new("PyPI")));

        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), content).unwrap();

        let dependencies = analyzer
            .analyze_dependencies_file(temp_file.path())
            .await
            .unwrap();

        // Should find flask, requests, and django (numpy doesn't match == pattern)
        assert!(dependencies.len() >= 3);

        let flask_dep = dependencies.iter().find(|d| d.name == "flask");
        assert!(flask_dep.is_some());
        assert_eq!(flask_dep.unwrap().version, "2.0.1");
    }

    #[tokio::test]
    async fn test_vulnerability_detection() {
        let mut analyzer = DependencyAnalyzer::new(DependencyAnalysisConfig {
            enable_caching: false,
            cache_ttl_seconds: 0,
            check_vulnerabilities: true,
            check_outdated: true,
        });

        analyzer.add_registry_client("npm", Box::new(MockRegistryClient::new("npm")));

        let content = r#"{
            "name": "test-app",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": {
                    "dependencies": {
                        "express": "4.18.0"
                    }
                },
                "node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                    "integrity": "sha512-..."
                }
            },
            "dependencies": {
                "express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz"
                }
            }
        }"#;

        // Simplified parsing for test - would need full implementation in production
        let dep_info = analyzer
            .analyze_single_dependency("express", "4.18.0", "npm")
            .await
            .unwrap();

        assert_eq!(dep_info.name, "express");
        assert_eq!(dep_info.version, "4.18.0");
        assert!(dep_info.is_outdated); // 4.18.0 < 4.18.2
        assert!(!dep_info.vulnerabilities.is_empty()); // Should have vulnerabilities
    }
}
