# Asset Inventory Management Plan

## Overview
This plan outlines the implementation of asset inventory management for the open-re security scanning platform. The system will track discovered assets (services, endpoints, technologies), deduplicate them, track asset-finding relationships, and expose asset tracking via CLI.

## 1. Storage Layer Modifications

### Files to Modify:
- `crates/openre-storage/src/lib.rs`
- `crates/openre-storage/src/project.rs`

### Implementation Details:

#### lib.rs
```rust
// Add asset module
pub mod asset;

// Export asset types
pub use asset::*;
```

#### project.rs
Add asset tables to the schema:
```rust
// In create_schema function:
// Assets table
conn.execute(
    r#"
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        target TEXT NOT NULL,
        technology TEXT,
        version TEXT,
        metadata_json TEXT NOT NULL,
        first_seen TIMESTAMP NOT NULL,
        last_seen TIMESTAMP NOT NULL,
        scan_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        tags_json TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    "#,
    [],
)?;

// Asset-Finding relationship table
conn.execute(
    r#"
    CREATE TABLE IF NOT EXISTS asset_findings (
        asset_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (asset_id, finding_id),
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
    )
    "#,
    [],
)?;

// Indexes
conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target)", [])?;
conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_technology ON assets(technology)", [])?;
conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id)", [])?;
conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_active ON assets(is_active)", [])?;
conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_findings_asset ON asset_findings(asset_id)", [])?;
conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_findings_finding ON asset_findings(finding_id)", [])?;
```

Add AssetStore trait implementation to ProjectStore:
```rust
impl ProjectStore {
    // Asset CRUD operations
    pub async fn add_asset(&self, asset: &Asset) -> Result<()> {
        // Implementation
    }
    
    pub async fn get_asset(&self, asset_id: &AssetId) -> Result<Option<Asset>> {
        // Implementation
    }
    
    pub async fn update_asset(&self, asset: &Asset) -> Result<()> {
        // Implementation
    }
    
    pub async fn delete_asset(&self, asset_id: &AssetId) -> Result<bool> {
        // Implementation
    }
    
    pub async fn list_assets(
        &self, 
        project_id: Option<ProjectId>,
        active_only: bool,
        limit: usize,
        offset: usize
    ) -> Result<Vec<Asset>> {
        // Implementation
    }
    
    pub async fn deduplicate_assets(&self, project_id: ProjectId) -> Result<usize> {
        // Implementation
    }
    
    pub async fn get_asset_findings(&self, asset_id: &AssetId) -> Result<Vec<Finding>> {
        // Implementation
    }
    
    pub async fn add_asset_finding(&self, asset_id: &AssetId, finding_id: &FindingId) -> Result<()> {
        // Implementation
    }
}
```

## 2. Core Definitions

### Files to Modify:
- `crates/openre-core/src/ids.rs`
- `crates/openre-core/src/lib.rs`
- `crates/openre-core/src/traits.rs`
- `crates/openre-core/src/result.rs`

### Implementation Details:

#### ids.rs
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub Uuid);

impl AssetId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
    
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}
```

#### lib.rs
```rust
// Add asset module
pub mod asset;

// Export asset types
pub use asset::*;
```

Create asset.rs:
```rust
use crate::ids::{AssetId, ProjectId, ScanId};
use crate::result::Finding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Asset type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    Service,
    Endpoint,
    Technology,
    Domain,
    IPAddress,
    CloudResource,
    Container,
    Database,
    API,
    Custom(String),
}

/// Represents a discovered asset during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: AssetId,
    pub name: String,
    pub asset_type: AssetType,
    pub target: String, // URL, IP, hostname, etc.
    pub technology: Option<String>,
    pub version: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub scan_id: ScanId, // Which scan discovered this asset
    pub project_id: ProjectId,
    pub tags: Vec<String>,
    pub is_active: bool,
}

/// Trait for asset storage operations
#[async_trait::async_trait]
pub trait AssetStorage {
    async fn add_asset(&self, asset: &Asset) -> OpenreResult<()>;
    async fn get_asset(&self, asset_id: &AssetId) -> OpenreResult<Option<Asset>>;
    async fn update_asset(&self, asset: &Asset) -> OpenreResult<()>;
    async fn delete_asset(&self, asset_id: &AssetId) -> OpenreResult<bool>;
    async fn list_assets(
        &self, 
        project_id: Option<ProjectId>,
        active_only: bool,
        limit: usize,
        offset: usize
    ) -> OpenreResult<Vec<Asset>>;
    async fn deduplicate_assets(&self, project_id: ProjectId) -> OpenreResult<usize>;
    async fn get_asset_findings(&self, asset_id: &AssetId) -> OpenreResult<Vec<Finding>>;
    async fn add_asset_finding(&self, asset_id: &AssetId, finding_id: &FindingId) -> OpenreResult<()>;
}
```

#### traits.rs
Add AssetStorage trait to the traits module:
```rust
pub use openre_core::asset::AssetStorage;
```

#### result.rs
Optionally add asset_id to Finding:
```rust
pub struct Finding {
    // ... existing fields ...
    /// Optional asset ID this finding is associated with
    pub asset_id: Option<AssetId>,
    // ... rest of fields ...
}

impl Finding {
    // Update new() method to accept asset_id
    pub fn new(config: FindingConfig, asset_id: Option<AssetId>) -> Self {
        // ... existing initialization ...
        Self {
            // ... existing fields ...
            asset_id,
            // ... rest of fields ...
        }
    }
    
    // Add with_asset_id method
    pub fn with_asset_id(mut self, asset_id: AssetId) -> Self {
        self.asset_id = Some(asset_id);
        self
    }
}
```

## 3. Scan Integration

### Files to Modify:
- `crates/openre-scan/src/lib.rs`
- `crates/openre-scan/src/scanner.rs`
- `crates/openre-scan/src/runner.rs`
- `crates/openre-scan/src/checks/` (various check files)

### Implementation Details:

#### lib.rs
```rust
// Export asset types
pub use openre_core::asset::{Asset, AssetType, AssetStorage};
```

#### scanner.rs
Modify ScanResult to include assets:
```rust
/// Scan result containing findings and assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    // ... existing fields ...
    /// Assets discovered during the scan
    pub assets: Vec<openre_core::asset::Asset>,
    // ... rest of fields ...
}

impl ScanResult {
    pub fn new(
        target: String,
        profile: crate::profiles::ScanProfile,
        findings: Vec<openre_core::result::Finding>,
        assets: Vec<openre_core::asset::Asset>,
        duration_ms: u64,
    ) -> Self {
        // ... existing severity count calculation ...
        Self {
            // ... existing fields ...
            assets,
            // ... rest of fields ...
        }
    }
}
```

#### runner.rs
Add asset extraction logic:
```rust
use openre_core::asset::{Asset, AssetType};

// Internal scan function - modify to return assets as well
pub async fn run_scan_internal(
    target_str: String,
    profile: crate::profiles::ScanProfile,
    _format: OutputFormat,
    timeout: u64,
    max_redirects: usize,
    user_agent: String,
) -> Result<(Vec<Finding>, Vec<Asset>)> {
    // ... existing target URL parsing ...
    
    let client = build_client(timeout, max_redirects, false, user_agent, None)?;
    
    let all_checks = get_all_checks(&profile);
    let checks_to_run: Vec<Check> =
        all_checks.into_iter().filter(|c| c.name() != "sensitive-files").collect();

    let mut all_findings = Vec::new();
    let mut all_assets = Vec::new();

    for check in checks_to_run {
        match check.run(&client, &target_url).await {
            Ok(findings) => {
                // Extract assets from findings
                let mut check_assets = extract_assets_from_findings(&findings);
                all_findings.extend(findings);
                all_assets.append(&mut check_assets);
            }
            Err(e) => eprintln!("Check {} failed: {}", check.name(), e),
        }
    }

    // Deduplicate assets
    let deduplicated_assets = deduplicate_assets(all_assets);
    
    Ok((all_findings, deduplicated_assets))
}

// Helper function to extract assets from findings
fn extract_assets_from_findings(findings: &[Finding]) -> Vec<Asset> {
    let mut assets = Vec::new();
    
    for finding in findings {
        // Extract endpoint asset from target
        if let Ok(url) = url::Url::parse(&finding.target) {
            assets.push(Asset {
                id: AssetId::new(),
                name: format!("{} endpoint", url.host_str().unwrap_or("unknown")),
                asset_type: AssetType::Endpoint,
                target: finding.target.clone(),
                technology: None,
                version: None,
                metadata: finding.metadata.clone(),
                first_seen: finding.timestamp,
                last_seen: finding.timestamp,
                scan_id: finding.scan_id,
                project_id: ProjectId::new(), // Would come from context
                tags: finding.tags.clone(),
                is_active: true,
            });
        }
        
        // Extract technology from evidence or metadata
        if let Some(tech) = finding.metadata.get("technology") {
            if let Some(tech_str) = tech.as_str() {
                assets.push(Asset {
                    id: AssetId::new(),
                    name: format!("{} technology", tech_str),
                    asset_type: AssetType::Technology,
                    target: finding.target.clone(),
                    technology: Some(tech_str.to_string()),
                    version: finding.metadata.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    metadata: finding.metadata.clone(),
                    first_seen: finding.timestamp,
                    last_seen: finding.timestamp,
                    scan_id: finding.scan_id,
                    project_id: ProjectId::new(), // Would come from context
                    tags: vec![format!("tech:{tech_str}")],
                    is_active: true,
                });
            }
        }
        
        // Extract from HTTP evidence
        for evidence in &finding.evidence {
            if let Some(server_header) = evidence.metadata.get("server") {
                if let Some(server_str) = server_header.as_str() {
                    // Parse server header for technology info
                    // Example: "nginx/1.18.0" -> technology: "nginx", version: "1.18.0"
                    let parts: Vec<&str> = server_str.split('/').collect();
                    if parts.len() >= 2 {
                        assets.push(Asset {
                            id: AssetId::new(),
                            name: format!("{} server", parts[0]),
                            asset_type: AssetType::Technology,
                            target: finding.target.clone(),
                            technology: Some(parts[0].to_string()),
                            version: Some(parts[1].to_string()),
                            metadata: evidence.metadata.clone(),
                            first_seen: evidence.timestamp,
                            last_seen: evidence.timestamp,
                            scan_id: finding.scan_id,
                            project_id: ProjectId::new(), // Would come from context
                            tags: vec![format!("server:{}", parts[0])],
                            is_active: true,
                        });
                    }
                }
            }
        }
    }
    
    assets
}

// Helper function to deduplicate assets
fn deduplicate_assets(mut assets: Vec<Asset>) -> Vec<Asset> {
    use std::collections::HashMap;
    
    // Key: (target, technology, version)
    let mut seen: HashMap<(String, Option<String>, Option<String>), Asset> = HashMap::new();
    
    for asset in assets.drain(..) {
        let key = (
            asset.target.clone(),
            asset.technology.clone(),
            asset.version.clone(),
        );
        
        if let Some(existing) = seen.get_mut(&key) {
            // Update existing asset
            existing.last_seen = asset.last_seen;
            existing.metadata.extend(asset.metadata);
            existing.tags.extend(asset.tags);
            existing.tags.dedup();
        } else {
            seen.insert(key, asset);
        }
    }
    
    seen.into_values().collect()
}

// Modify main scan function to handle assets
pub async fn run_scan(config: ScanConfig, scanner_config: &ScannerConfig) -> Result<()> {
    // ... existing setup ...
    
    let (all_findings, all_assets) = run_scan_internal(
        target_str,
        profile,
        output_format,
        timeout,
        max_redirects,
        user_agent,
    )
    .await?;
    
    // Store assets via history storage
    if let Some(history) = &history_storage {
        for asset in &all_assets {
            // Set proper project_id from config
            let mut asset_with_project = asset.clone();
            asset_with_project.project_id = config.project_id.unwrap_or_else(|| ProjectId::new());
            history.add_asset(&asset_with_project).await?;
            
            // Link assets to findings (simplified - in practice would need better matching)
            for finding in &all_findings {
                if finding.target.contains(&asset.target) || 
                   asset.technology.as_ref().map_or(false, |t| finding.metadata.get("technology").and_then(|v| v.as_str()).map_or(false, |tech| tech == t)) {
                    history.add_asset_finding(&asset.id, &finding.id).await?;
                }
            }
        }
    }
    
    // Update ScanResult to include assets
    let scan_result = ScanResult::new(
        target_url.to_string(),
        profile,
        all_findings,
        all_assets,
        duration.as_millis() as u64,
    );
    
    // ... existing display and output logic ...
    
    Ok(())
}
```

#### checks/
Individual checks would need to be modified to return assets in their findings metadata, but the extraction logic in runner.rs handles this generically.

## 4. CLI Integration

### Files to Modify:
- `crates/openre-cli/src/commands/mod.rs`
- `crates/openre-cli/src/commands/assets.rs` (new file)
- `crates/openre-cli/src/context.rs`
- `crates/openre-cli/src/output.rs`

### Implementation Details:

#### commands/mod.rs
Add assets subcommand:
```rust
pub mod assets;
```

In the Commands enum:
```rust
#[derive(Debug)]
pub enum Commands {
    // ... existing commands ...
    Assets(assets::AssetsCommand),
}
```

In the match statement:
```rust
Commands::Assets(cmd) => cmd.run(matches, context).await?,
```

#### commands/assets.rs (new file)
```rust
use crate::context::AppContext;
use crate::error::CliResult;
use openre_core::ids::{AssetId, ProjectId};
use openre_storage::AssetStorage;
use std::str::FromStr;

#[derive(Debug)]
pub struct AssetsCommand;

impl AssetsCommand {
    pub async fn run(&self, matches: &clap::ArgMatches, context: &AppContext) -> CliResult<()> {
        match matches.subcommand() {
            ("list", Some(sub_matches)) => self.list_assets(sub_matches, context).await,
            ("show", Some(sub_matches)) => self.show_asset(sub_matches, context).await,
            ("delete", Some(sub_matches)) => self.delete_asset(sub_matches, context).await,
            ("export", Some(sub_matches)) => self.export_assets(sub_matches, context).await,
            ("stats", Some(sub_matches)) => self.show_stats(sub_matches, context).await,
            _ => Err("Invalid assets subcommand".into()),
        }
    }
    
    async fn list_assets(&self, matches: &clap::ArgMatches, context: &AppContext) -> CliResult<()> {
        let active_only = matches.get_flag("active");
        let limit = matches.get_one::<usize>("limit").copied().unwrap_or(100);
        let offset = matches.get_one::<usize>("offset").copied().unwrap_or(0);
        
        let assets = context
            .storage
            .list_assets(None, active_only, limit, offset)
            .await?;
        
        crate::output::print_asset_table(&assets);
        Ok(())
    }
    
    async fn show_asset(&self, matches: &clap::ArgMatches, context: &AppContext) -> CliResult<()> {
        let id_str = matches.get_one::<String>("id").expect("required");
        let asset_id = AssetId::from_str(id_str)
            .map_err(|_| format!("Invalid asset ID: {}", id_str))?;
            
        let asset = context
            .storage
            .get_asset(&asset_id)
            .await?
            .ok_or_else(|| format!("Asset not found: {}", id_str))?;
            
        crate::output::print_asset_detail(&asset);
        Ok(())
    }
    
    async fn delete_asset(&self, matches: &clap::ArgMatches, context: &AppContext) -> CliResult<()> {
        let id_str = matches.get_one::<String>("id").expect("required");
        let asset_id = AssetId::from_str(id_str)
            .map_err(|_| format!("Invalid asset ID: {}", id_str))?;
            
        let deleted = context.storage.delete_asset(&asset_id).await?;
        if deleted {
            println!("Asset {} deleted successfully", id_str);
        } else {
            println!("Asset {} not found", id_str);
        }
        Ok(())
    }
    
    async fn export_assets(&self, matches: &clap::ArgMatches, context: &AppContext) -> CliResult<()> {
        let format = matches.get_one::<String>("format").expect("required");
        let active_only = matches.get_flag("active");
        
        let assets = context
            .storage
            .list_assets(None, active_only, usize::MAX, 0)
            .await?;
        
        match format.as_str() {
            "json" => {
                let json = serde_json::to_string_pretty(&assets)?;
                println!("{}", json);
            }
            "csv" => {
                println!("id,name,asset_type,target,technology,version,first_seen,last_seen,tags");
                for asset in &assets {
                    println!(
                        "{},{},{},{},{},{},{},{},{}",
                        asset.id.0,
                        asset.name.replace(',', " "),
                        format!("{:?}", asset.asset_type),
                        asset.target.replace(',', " "),
                        asset.technology.as_deref().unwrap_or(""),
                        asset.version.as_deref().unwrap_or(""),
                        asset.first_seen.to_rfc3339(),
                        asset.last_seen.to_rfc3339(),
                        asset.tags.join(";")
                    );
                }
            }
            _ => return Err(format!("Unsupported format: {}", format).into()),
        }
        Ok(())
    }
    
    async fn show_stats(&self, _matches: &clap::ArgMatches, context: &AppContext) -> CliResult<()> {
        // Get all assets for stats
        let assets = context.storage.list_assets(None, true, usize::MAX, 0).await?;
        
        let total = assets.len();
        let by_type = assets.iter()
            .fold(std::collections::HashMap::new(), |mut acc, asset| {
                *acc.entry(format!("{:?}", asset.asset_type)).or_insert(0) += 1;
                acc
            });
        let by_technology = assets.iter()
            .filter_map(|a| a.technology.as_ref())
            .fold(std::collections::HashMap::new(), |mut acc, tech| {
                *acc.entry(tech.clone()).or_insert(0) += 1;
                acc
            });
        
        println!("Asset Statistics:");
        println!("  Total assets: {}", total);
        println!("  By type:");
        for (typ, count) in &by_type {
            println!("    {}: {}", typ, count);
        }
        println!("  By technology:");
        for (tech, count) in &by_technology {
            println!("    {}: {}", tech, count);
        }
        Ok(())
    }
}
```

#### context.rs
Add storage to context:
```rust
pub struct AppContext {
    // ... existing fields ...
    pub storage: Arc<dyn openre_storage::AssetStorage + Send + Sync>,
    // ... rest of fields ...
}
```

#### output.rs
Add asset display functions:
```rust
use prettytable::{Table, Row, Cell};
use openre_core::asset::{Asset, AssetType};

pub fn print_asset_table(assets: &[Asset]) {
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("ID"),
        Cell::new("Name"),
        Cell::new("Type"),
        Cell::new("Target"),
        Cell::new("Technology"),
        Cell::new("Version"),
        Cell::new("First Seen"),
        Cell::new("Last Seen"),
        Cell::new("Tags"),
    ]));
    
    for asset in assets {
        table.add_row(Row::new(vec![
            Cell::new(&asset.id.0.to_string()),
            Cell::new(&asset.name),
            Cell::new(&format!("{:?}", asset.asset_type)),
            Cell::new(&asset.target),
            Cell::new(&asset.technology.as_deref().unwrap_or(&"-".to_string())),
            Cell::new(&asset.version.as_deref().unwrap_or(&"-".to_string())),
            Cell::new(&asset.first_seen.to_rfc3339()),
            Cell::new(&asset.last_seen.to_rfc3339()),
            Cell::new(&asset.tags.join(", ")),
        ]));
    }
    
    table.printstd();
}

pub fn print_asset_detail(asset: &Asset) {
    println!("Asset Details:");
    println!("  ID: {}", asset.id.0);
    println!("  Name: {}", asset.name);
    println!("  Type: {:?}", asset.asset_type);
    println!("  Target: {}", asset.target);
    println!("  Technology: {}", asset.technology.as_deref().unwrap_or(&"None".to_string()));
    println!("  Version: {}", asset.version.as_deref().unwrap_or(&"None".to_string()));
    println!("  First Seen: {}", asset.first_seen.to_rfc3339());
    println!("  Last Seen: {}", asset.last_seen.to_rfc3339());
    println!("  Scan ID: {}", asset.scan_id.0);
    println!("  Project ID: {}", asset.project_id.0);
    println!("  Tags: {}", asset.tags.join(", "));
    println!("  Active: {}", asset.is_active);
    println!("  Metadata: {}", serde_json::to_string_pretty(&asset.metadata).unwrap_or_default());
}
```

Update Cargo.toml files to add dependencies:
- Add prettytable to openre-cli
- Add async-trait to openre-core if not present
- Add chrono, serde, serde_json, uuid to relevant crates

## 5. Asset Deduplication Strategy

The deduplication strategy uses a composite key consisting of:
1. Target (URL, IP, hostname)
2. Technology (if applicable)
3. Version (if applicable)

When adding a new asset:
1. Generate the composite key
2. Check if an asset with the same key exists in the project
3. If exists:
   - Update last_seen to current timestamp
   - Merge metadata (new values overwrite existing)
   - Merge tags (remove duplicates)
   - Keep the earliest first_seen
4. If not exists:
   - Create new asset with current timestamps

This approach ensures that:
- The same endpoint discovered across multiple scans is tracked as one asset
- Technology versions are properly tracked
- Historical data is preserved
- Assets can be reactivated if rediscovered after being marked inactive

## 6. Asset-Finding Relationship Tracking

Relationships are tracked through:
1. Optional asset_id field in Finding struct
2. asset_findings junction table in storage

When processing scan results:
1. For each finding, determine which asset(s) it relates to
   - Direct match: finding.target contains asset.target
   - Technology match: finding.metadata.technology matches asset.technology
   - Evidence-based: HTTP server headers match asset technology
2. For each matched asset-finding pair:
   - Set finding.asset_id = Some(asset.id)
   - Insert record into asset_findings table

Queries supported:
- Get all findings for an asset: SELECT findings.* FROM findings JOIN asset_findings ON findings.id = asset_findings.finding_id WHERE asset_findings.asset_id = ?
- Get all assets for a finding: SELECT assets.* FROM assets JOIN asset_findings ON assets.id = asset_findings.asset_id WHERE asset_findings.finding_id = ?

This enables powerful queries like:
- "Show all findings for my web server assets"
- "Show which assets have critical findings"
- "Track asset risk over time based on associated findings"

## 7. Implementation Timeline

### Week 1: Storage Layer
- Define Asset struct and AssetId
- Implement AssetStorage trait
- Add asset tables to ProjectStore schema
- Implement basic CRUD operations
- Unit tests for storage layer

### Week 2: Scan Integration
- Modify ScanResult to include assets
- Implement asset extraction in runner
- Add asset storage to scan workflow
- Link assets to findings
- Integration tests

### Week 3: CLI Implementation
- Create assets command with subcommands
- Add storage to CLI context
- Implement output formatting
- Manual testing

### Week 4: Polish and Documentation
- Deduplication refinement
- Performance optimization
- Documentation updates
- Final testing

## 8. Backward Compatibility

All changes are backward compatible:
- New tables added to existing schemas
- New fields added as optional to existing structs
- No existing APIs removed or modified
- CLI adds new subcommand without changing existing ones
- Storage layer uses Option types for new relationships

## 9. Security Considerations

- Asset data is stored alongside existing scan data with same protection
- No new attack surfaces introduced
- Asset information is derived from scan data already being collected
- Access controlled through existing project/scan permissions

## 10. Usage Examples

### CLI Usage
```bash
# List all assets
openre assets list

# List only active assets
openre assets list --active

# Show specific asset details
openre assets show <asset-id>

# Delete an asset
openre assets delete <asset-id>

# Export assets as JSON
openre assets export --format json > assets.json

# Export assets as CSV
openre assets export --format csv > assets.csv

# Show asset statistics
openre assets stats
```

### Programmatic Usage
```rust
let context = AppContext::from_config(&config)?;
let storage = context.storage;

// Add a new asset
let asset = Asset {
    id: AssetId::new(),
    name: "Web Server".to_string(),
    asset_type: AssetType::Service,
    target: "https://example.com".to_string(),
    technology: Some("nginx".to_string()),
    version: Some("1.18.0".to_string()),
    metadata: serde_json::json!({ "header": "nginx/1.18.0" }),
    first_seen: Utc::now(),
    last_seen: Utc::now(),
    scan_id: ScanId::new(),
    project_id: ProjectId::new(),
    tags: vec!["web".to_string(), "production".to_string()],
    is_active: true,
};

storage.add_asset(&asset).await?;

// Get assets for a project
let assets = storage.list_assets(Some(project_id), true, 100, 0).await?;

// Get findings for an asset
let findings = storage.get_asset_findings(&asset.id).await?;

// Link a finding to an asset
storage.add_asset_finding(&asset.id, &finding_id).await?;
```