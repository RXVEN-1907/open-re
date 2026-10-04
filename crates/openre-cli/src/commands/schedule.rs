#![allow(clippy::too_many_lines)]

//! Schedule management commands for continuous monitoring
//!
//! This module provides commands to manage scheduled scans for continuous monitoring.

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::error::OpenreResult;
use openre_core::ids::{ProjectId, ScanId, TargetId};
use openre_core::history::{HistoryStorage, ScanConfigSummary, ScanProgressSummary, ScanSummary};
use openre_core::result::Finding;
use openre_core::result::Severity;
use openre_scan::checks::get_all_checks;
use openre_scan::client::{build_client, build_client_with_config};
use openre_scan::config::ScanConfig;
use openre_scan::{ScanProfile, ScanResult, ScanTarget, Scanner};
use openre_storage::history::SqliteHistoryStorage;
use rusqlite::{params, params_from_iter, Connection};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tabled::{settings::Style, Table};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

/// Get history storage for scan operations
fn get_history_storage(ctx: &Context) -> SqliteHistoryStorage {
    let db_path = ctx.config.storage.local_path.join("history.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create history directory");
    }
    SqliteHistoryStorage::new(&db_path).expect("Failed to create history storage")
}

/// Get scheduled scans storage path
fn get_schedule_storage_path(ctx: &Context) -> PathBuf {
    let path = ctx.config.storage.local_path.join("schedules.db");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create schedules directory");
    }
    path
}

/// Initialize scheduled scans database
async fn init_schedule_storage(ctx: &Context) -> OpenreResult<SqliteHistoryStorage> {
    let db_path = get_schedule_storage_path(ctx);
    let storage = SqliteHistoryStorage::new(&db_path)?;

    // Create schedules table if it doesn't exist
    let mut conn = storage.conn().await;

    // Schedules table

    // Schedules table
    conn.execute(
        r#"
        CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            profile TEXT NOT NULL,
            interval_minutes INTEGER NOT NULL,
            checks TEXT,
            exclude_checks TEXT,
            headers TEXT,
            user_agent TEXT,
            proxy TEXT,
            timeout INTEGER,
            rate_limit REAL,
            max_redirects INTEGER,
            follow_redirects INTEGER,
            no_tls_verify INTEGER,
            enabled INTEGER DEFAULT 1,
            last_run TIMESTAMP,
            next_run TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        [],
    )?;

    // Schedule runs table for tracking execution history
    conn.execute(
        r#"
        CREATE TABLE IF NOT EXISTS schedule_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'running',
            findings_count INTEGER DEFAULT 0,
            new_findings INTEGER DEFAULT 0,
            fixed_findings INTEGER DEFAULT 0,
            FOREIGN KEY (schedule_id) REFERENCES schedules(id),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        "#,
        [],
    )?;

    drop(conn);
    Ok(storage)
}

/// Scan schedule definition
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanSchedule {
    pub id: String,
    pub name: String,
    pub target: String,
    pub profile: String,
    pub interval_minutes: u64,
    pub checks: Option<Vec<String>>,
    pub exclude_checks: Option<Vec<String>>,
    pub headers: Option<Vec<(String, String)>>,
    pub user_agent: Option<String>,
    pub proxy: Option<String>,
    pub timeout: Option<u64>,
    pub rate_limit: Option<f64>,
    pub max_redirects: Option<usize>,
    pub follow_redirects: Option<bool>,
    pub no_tls_verify: bool,
    pub enabled: bool,
    pub last_run: Option<chrono::DateTime<chrono::Utc>>,
    pub next_run: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Schedule run record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScheduleRun {
    pub id: i64,
    pub schedule_id: String,
    pub scan_id: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
    pub findings_count: usize,
    pub new_findings: usize,
    pub fixed_findings: usize,
}

/// Schedule-related commands
#[derive(Subcommand, Debug)]
pub enum ScheduleCommands {
    /// Add a new scan schedule
    Add(ScheduleAddArgs),
    /// List all scan schedules
    List(ScheduleListArgs),
    /// Remove a scan schedule
    Remove(ScheduleRemoveArgs),
    /// Pause a scan schedule
    Pause(SchedulePauseArgs),
    /// Resume a scan schedule
    Resume(ScheduleResumeArgs),
    /// Show details of a scan schedule
    Show(ScheduleShowArgs),
    /// Run the scheduler daemon (internal command)
    Daemon(ScheduleDaemonArgs),
}

/// Arguments for adding a schedule
#[derive(Args, Debug)]
struct ScheduleAddArgs {
    /// Target URL or domain
    target: String,

    /// Name for the schedule
    #[arg(short, long)]
    name: String,

    /// Scan profile (quick, standard, full)
    #[arg(long, value_enum, default_value_t = ScheduleProfileArg::Standard)]
    profile: ScheduleProfileArg,

    /// Interval between scans in minutes
    #[arg(short, long, default_value_t = 60)]
    interval: u64,

    /// Checks to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    checks: Vec<String>,

    /// Checks to exclude (comma-separated)
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Custom headers (can be repeated, format: "Key: Value")
    #[arg(long, value_name = "HEADER")]
    header: Vec<String>,

    /// Request timeout in seconds
    #[arg(long)]
    timeout: Option<u64>,

    /// Follow redirects
    #[arg(long)]
    follow_redirects: Option<bool>,

    /// Maximum redirect depth
    #[arg(long)]
    max_redirects: Option<usize>,

    /// User agent string
    #[arg(long)]
    user_agent: Option<String>,

    /// Proxy URL (e.g., http://127.0.0.1:8080)
    #[arg(long)]
    proxy: Option<String>,

    /// Rate limit (requests per second)
    #[arg(long)]
    rate_limit: Option<f64>,

    /// Disable TLS verification
    #[arg(long)]
    no_tls_verify: bool,
}

/// Arguments for listing schedules
#[derive(Args, Debug)]
struct ScheduleListArgs {
    /// Show only enabled schedules
    #[arg(long)]
    enabled_only: bool,

    /// Show only disabled schedules
    #[arg(long)]
    disabled_only: bool,
}

/// Arguments for removing a schedule
#[derive(Args, Debug)]
struct ScheduleRemoveArgs {
    /// Schedule ID to remove
    id: String,
}

/// Arguments for pausing a schedule
#[derive(Args, Debug)]
struct SchedulePauseArgs {
    /// Schedule ID to pause
    id: String,
}

/// Arguments for resuming a schedule
#[derive(Args, Debug)]
struct ScheduleResumeArgs {
    /// Schedule ID to resume
    id: String,
}

/// Arguments for showing schedule details
#[derive(Args, Debug)]
struct ScheduleShowArgs {
    /// Schedule ID to show
    id: String,
}

/// Arguments for the scheduler daemon
#[derive(Args, Debug)]
struct ScheduleDaemonArgs {
    /// Run once and exit (don't daemonize)
    #[arg(long)]
    once: bool,
}

/// Schedule profile argument
#[derive(Debug, Clone, ValueEnum)]
enum ScheduleProfileArg {
    Quick,
    Standard,
    Full,
}

impl From<ScheduleProfileArg> for ScanProfile {
    fn from(p: ScheduleProfileArg) -> Self {
        match p {
            ScheduleProfileArg::Quick => ScanProfile::Quick,
            ScheduleProfileArg::Standard => ScanProfile::Standard,
            ScheduleProfileArg::Full => ScanProfile::Full,
        }
    }
}

impl ScheduleCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ScheduleCommands::Add(args) => add_schedule(ctx, args).await,
            ScheduleCommands::List(args) => list_schedules(ctx, args).await,
            ScheduleCommands::Remove(args) => remove_schedule(ctx, args).await,
            ScheduleCommands::Pause(args) => pause_schedule(ctx, args).await,
            ScheduleCommands::Resume(args) => resume_schedule(ctx, args).await,
            ScheduleCommands::Show(args) => show_schedule(ctx, args).await,
            ScheduleCommands::Daemon(args) => run_scheduler_daemon(ctx, args).await,
        }
    }
}

/// Add a new scan schedule
async fn add_schedule(ctx: Context, args: ScheduleAddArgs) -> Result<(), CliError> {
    let storage = init_schedule_storage(&ctx).await?;

    // Generate a unique schedule ID
    let schedule_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let next_run = now + chrono::Duration::minutes(args.interval as i64);

    // Parse headers
    let mut headers = Vec::new();
    for h in args.header {
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    // Create schedule record
    let schedule = ScanSchedule {
        follow_redirects: args.follow_redirects,
        id: schedule_id.clone(),
        name: args.name,
        profile: match args.profile {
            ScheduleProfileArg::Quick => "quick".to_string(),
            ScheduleProfileArg::Standard => "standard".to_string(),
            ScheduleProfileArg::Full => "full".to_string(),
        },
        interval_minutes: args.interval,
        checks: if args.checks.is_empty() { None } else { Some(args.checks) },
        exclude_checks: if args.exclude.is_empty() { None } else { Some(args.exclude) },
        headers: if headers.is_empty() { None } else { Some(headers) },
        user_agent: args.user_agent,
        proxy: args.proxy,
        timeout: args.timeout,
        rate_limit: args.rate_limit,
        max_redirects: args.max_redirects,
        follow_redirects: args.follow_redirects,
        no_tls_verify: args.no_tls_verify,
        enabled: true,
        last_run: None,
        next_run: Some(next_run),
        created_at: now,
        updated_at: now,

    conn.execute(
        r#"
        INSERT INTO schedules (
            id, name, target, profile, interval_minutes, checks, exclude_checks,
            headers, user_agent, proxy, timeout, rate_limit, max_redirects,
            follow_redirects, no_tls_verify, enabled, last_run, next_run,
            created_at, updated_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
        )
        "#,
        params![
            &schedule.id,
            &schedule.name,
            &schedule.target,
            &schedule.profile,
            schedule.interval_minutes as i64,
            &serde_json::to_string(&schedule.checks)?,
            &serde_json::to_string(&schedule.exclude_checks)?,
            &serde_json::to_string(&schedule.headers)?,
            schedule.user_agent.as_deref(),
            schedule.proxy.as_deref(),
            schedule.timeout.map(|v| v as i64),
            schedule.rate_limit,
            schedule.max_redirects.map(|v| v as i64),
            schedule.follow_redirects.map(|v| v as i64),
            schedule.no_tls_verify as i64,
            schedule.enabled as i64,
            schedule.last_run.map(|dt| dt.to_rfc3339()).as_deref(),
            schedule.next_run.map(|dt| dt.to_rfc3339()).as_deref(),
            &schedule.created_at.to_rfc3339(),
            &schedule.updated_at.to_rfc3339(),
        ]
    )?;

    println!("  {} {}", "Next run:".bold(), next_run.to_rfc3339());
    println!("  {} {}", "Target:".bold(), args.target);
    let profile_str = match args.profile {
        ScheduleProfileArg::Quick => "quick".to_string(),
        ScheduleProfileArg::Standard => "standard".to_string(),
        ScheduleProfileArg::Full => "full".to_string(),
    };
    println!("  {} {}", "Profile:".bold(), profile_str);
    println!("  {} {}", "Interval:".bold(), format!("{} minutes", args.interval));
    println!("  {} {}", "Next run:".bold(), next_run.to_rfc3339());

    Ok(())
}

/// List all scan schedules
async fn list_schedules(ctx: Context, args: ScheduleListArgs) -> Result<(), CliError> {
    let storage = init_schedule_storage(&ctx).await?;

    // Build query
    let mut query = "SELECT id, name, target, profile, interval_minutes, enabled, last_run, next_run FROM schedules".to_string();
    let mut conditions = Vec::new();

    if args.enabled_only {
        conditions.push("enabled = 1".to_string());
    }
    if args.disabled_only {
        conditions.push("enabled = 0".to_string());
    }

    if !conditions.is_empty() {
        query.push_str(" WHERE ");
        query.push_str(&conditions.join(" AND "));
    }

    query.push_str(" ORDER BY created_at DESC");

    // Execute query
    let mut conn = storage.conn().await;

    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, // id
            row.get::<_, String>(1)?, // name
            row.get::<_, String>(2)?, // target
            row.get::<_, String>(3)?, // profile
            row.get::<_, i64>(4)?,    // interval_minutes
            row.get::<_, i64>(5)?,    // enabled
            row.get::<_, Option<String>>(6)?, // last_run
            row.get::<_, Option<String>>(7)?, // next_run
        ))
    })?;

    let mut schedules = Vec::new();
    for row in rows {
        let (id, name, target, profile, interval, enabled, last_run, next_run) = row?;
        schedules.push((
            id,
            name,
            target,
            profile,
            interval as u64,
            enabled == 1,
            last_run.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
            next_run.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
        ));
    }


    if schedules.is_empty() {
        println!("{} No schedules found", "ℹ".blue().bold());
        return Ok(());
    }

    // Create table for display
    let mut table = Table::new(
        schedules.iter()
            .map(|(id, name, target, profile, interval, enabled, last_run, next_run)| {
                ScheduleListRow {
                    id: id.clone(),
                    name: name.clone(),
                    target: target.clone(),
                    profile: profile.clone(),
                    interval: format!("{}m", interval),
                    status: if *enabled { "Enabled".green().to_string() } else { "Disabled".red().to_string() },
                    last_run: last_run.map(|dt| dt.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Never".to_string()),
                    next_run: next_run.map(|dt| dt.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Not scheduled".to_string()),
                }
            })
            .collect::<Vec<_>>(),
    );
    table.with(Style::modern());
    println!("{}", table);

    Ok(())
}

/// Remove a scan schedule
async fn remove_schedule(ctx: Context, args: ScheduleRemoveArgs) -> Result<(), CliError> {
    let storage = init_schedule_storage(&ctx).await?;

    // Check if schedule exists
    let mut conn = storage.conn().await;

    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM schedules WHERE id = ?1",
        params![&args.id],
        |row| row.get(0),
    )?.unwrap_or(0) > 0;

    if !exists {
        return Err(CliError::NotFound(format!("Schedule not found: {}", args.id)));
    }

    // Delete the schedule
    conn.execute(
        "DELETE FROM schedules WHERE id = ?1",
        params![&args.id],
    )?;

    // Also delete associated schedule runs
    conn.execute(
        "DELETE FROM schedule_runs WHERE schedule_id = ?1",
        params![&args.id],
    )?;


    println!("{} Schedule removed: {}", "✓".green().bold(), args.id);

    Ok(())
}

/// Pause a scan schedule
async fn pause_schedule(ctx: Context, args: SchedulePauseArgs) -> Result<(), CliError> {
    let storage = init_schedule_storage(&ctx).await?;

    let mut conn = storage.conn().await;

    let mut schedule: Option<ScanSchedule> = conn.query_row(
        "SELECT id, name, target, profile, interval_minutes, checks, exclude_checks, headers, user_agent, proxy, timeout, rate_limit, max_redirects, follow_redirects, no_tls_verify, enabled, last_run, next_run, created_at, updated_at FROM schedules WHERE id = ?1",
        params![&args.id],
        |row| {
            Ok(ScanSchedule {
                id: row.get(0)?,
                name: row.get(1)?,
                target: row.get(2)?,
                profile: row.get(3)?,
                interval_minutes: row.get(4)? as u64,
                checks: {
                    let opt = row.get::<_, Option<String>>(5)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                exclude_checks: {
                    let opt = row.get::<_, Option<String>>(6)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                headers: {
                    let opt = row.get::<_, Option<String>>(7)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                user_agent: row.get(8)?,
                proxy: row.get(9)?,
                timeout: row.get(10)?.map(|v| v as u64),
                rate_limit: row.get(11)?,
                max_redirects: row.get(12)?.map(|v| v as usize),
                follow_redirects: row.get(13)?.map(|v| v != 0),
                no_tls_verify: row.get(14)? != 0,
                enabled: row.get(15)? != 0,
                last_run: row.get::<_, Option<String>>(16)?.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
                next_run: row.get::<_, Option<String>>(17)?.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get(18)?).unwrap().with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get(19)?).unwrap().with_timezone(&chrono::Utc),
            })
        },
    )?;

    if schedule.is_none() {
        return Err(CliError::NotFound(format!("Schedule not found: {}", args.id)));
    }

    let mut schedule = schedule.unwrap();
    if !schedule.enabled {
        return Err(CliError::InvalidArgs(format!("Schedule is already disabled: {}", args.id)));
    }

    schedule.enabled = false;
    schedule.updated_at = chrono::Utc::now();

    // Update in database
    conn.execute(
        r#"
        UPDATE schedules SET
            enabled = ?1,
            updated_at = ?2
        WHERE id = ?3
        "#,
        params![
            schedule.enabled as i64,
            &schedule.updated_at.to_rfc3339(),
            &schedule.id
        ]
    )?;


    println!("{} Schedule paused: {}", "✓".green().bold(), args.id);

    Ok(())
}

/// Resume a scan schedule
async fn resume_schedule(ctx: Context, args: ScheduleResumeArgs) -> Result<(), CliError> {
    let storage = init_schedule_storage(&ctx).await?;

    let mut conn = storage.conn().await;

    let mut schedule: Option<ScanSchedule> = conn.query_row(
        "SELECT id, name, target, profile, interval_minutes, checks, exclude_checks, headers, user_agent, proxy, timeout, rate_limit, max_redirects, follow_redirects, no_tls_verify, enabled, last_run, next_run, created_at, updated_at FROM schedules WHERE id = ?1",
        params![&args.id],
        |row| {
            Ok(ScanSchedule {
                id: row.get(0)?,
                name: row.get(1)?,
                target: row.get(2)?,
                profile: row.get(3)?,
                interval_minutes: row.get(4)? as u64,
                checks: {
                    let opt = row.get::<_, Option<String>>(5)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                exclude_checks: {
                    let opt = row.get::<_, Option<String>>(6)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                headers: {
                    let opt = row.get::<_, Option<String>>(7)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                user_agent: row.get(8)?,
                proxy: row.get(9)?,
                timeout: row.get(10)?.map(|v| v as u64),
                rate_limit: row.get(11)?,
                max_redirects: row.get(12)?.map(|v| v as usize),
                follow_redirects: row.get(13)?.map(|v| v != 0),
                no_tls_verify: row.get(14)? != 0,
                enabled: row.get(15)? != 0,
                last_run: row.get::<_, Option<String>>(16)?.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
                next_run: row.get::<_, Option<String>>(17)?.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get(18)?).unwrap().with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get(19)?).unwrap().with_timezone(&chrono::Utc),
            })
        },
    )?;

    if schedule.is_none() {
        return Err(CliError::NotFound(format!("Schedule not found: {}", args.id)));
    }

    let mut schedule = schedule.unwrap();
    if schedule.enabled {
        return Err(CliError::InvalidArgs(format!("Schedule is already enabled: {}", args.id)));
    }

    // Calculate next run time based on interval
    let now = chrono::Utc::now();
    let next_run = if let Some(last_run) = schedule.last_run {
        last_run + chrono::Duration::minutes(schedule.interval_minutes as i64)
    } else {
        now + chrono::Duration::minutes(schedule.interval_minutes as i64)
    };

    schedule.enabled = true;
    schedule.next_run = Some(next_run);
    schedule.updated_at = now;

    // Update in database
    conn.execute(
        r#"
        UPDATE schedules SET
            enabled = ?1,
            next_run = ?2,
            updated_at = ?3
        WHERE id = ?4
        "#,
        params![
            schedule.enabled as i64,
            schedule.next_run.map(|dt| dt.to_rfc3339()).as_deref(),
            &schedule.updated_at.to_rfc3339(),
            &schedule.id
        ]
    )?;


    println!("{} Schedule resumed: {}", "✓".green().bold(), args.id);
    println!("  {} {}", "Next run:".bold(), schedule.next_run.unwrap().to_rfc3339());

    Ok(())
}

/// Show details of a scan schedule
async fn show_schedule(ctx: Context, args: ScheduleShowArgs) -> Result<(), CliError> {
    let storage = init_schedule_storage(&ctx).await?;

    let mut conn = storage.conn().await;

    let schedule: Option<ScanSchedule> = conn.query_row(
        "SELECT id, name, target, profile, interval_minutes, checks, exclude_checks, headers, user_agent, proxy, timeout, rate_limit, max_redirects, follow_redirects, no_tls_verify, enabled, last_run, next_run, created_at, updated_at FROM schedules WHERE id = ?1",
        params![&args.id],
        |row| {
            Ok(ScanSchedule {
                id: row.get(0)?,
                name: row.get(1)?,
                target: row.get(2)?,
                profile: row.get(3)?,
                interval_minutes: row.get(4)? as u64,
                checks: {
                    let opt = row.get::<_, Option<String>>(5)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                exclude_checks: {
                    let opt = row.get::<_, Option<String>>(6)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                headers: {
                    let opt = row.get::<_, Option<String>>(7)?;
                    match opt {
                        Some(s) if s == "null" => None,
                        Some(s) => serde_json::from_str(&s).ok(),
                        None => None,
                    }
                },
                user_agent: row.get(8)?,
                proxy: row.get(9)?,
                timeout: row.get(10)?.map(|v| v as u64),
                rate_limit: row.get(11)?,
                max_redirects: row.get(12)?.map(|v| v as usize),
                follow_redirects: row.get(13)?.map(|v| v != 0),
                no_tls_verify: row.get(14)? != 0,
                enabled: row.get(15)? != 0,
                last_run: row.get::<_, Option<String>>(16)?.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
                next_run: row.get::<_, Option<String>>(17)?.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get(18)?).unwrap().with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get(19)?).unwrap().with_timezone(&chrono::Utc),
            })
        },
    )?;


    if schedule.is_none() {
        return Err(CliError::NotFound(format!("Schedule not found: {}", args.id)));
    }

    let schedule = schedule.unwrap();

    println!("{} Schedule Details: {}", "ℹ".blue().bold(), schedule.name);
    println!("{}", "═".repeat(50).dimmed());
    println!("  {} {}", "ID:".bold(), schedule.id);
    println!("  {} {}", "Name:".bold(), schedule.name);
    println!("  {} {}", "Target:".bold(), schedule.target);
    println!("  {} {}", "Profile:".bold(), schedule.profile);
    println!("  {} {}", "Interval:".bold(), format!("{} minutes", schedule.interval_minutes));
    println!("  {} {}", "Status:".bold(), if schedule.enabled { "Enabled".green() } else { "Disabled".red() });
    println!("  {} {}", "Created:".bold(), schedule.created_at.to_rfc3339());
    println!("  {} {}", "Updated:".bold(), schedule.updated_at.to_rfc3339());

    if let Some(last_run) = schedule.last_run {
        println!("  {} {}", "Last Run:".bold(), last_run.to_rfc3339());
    } else {
        println!("  {} {}", "Last Run:".bold(), "Never");
    }

    if let Some(next_run) = schedule.next_run {
        println!("  {} {}", "Next Run:".bold(), next_run.to_rfc3339());
    } else {
        println!("  {} {}", "Next Run:".bold(), "Not scheduled");
    }

    if let Some(checks) = &schedule.checks {
        println!("  {} {}", "Checks:".bold(), checks.join(", "));
    } else {
        println!("  {} {}", "Checks:".bold(), "All (profile default)");
    }

    if let Some(exclude) = &schedule.exclude_checks {
        println!("  {} {}", "Excluded Checks:".bold(), exclude.join(", "));
    }

    if let Some(headers) = &schedule.headers {
        println!("  {}", "Headers:".bold());
        for (k, v) in headers {
            println!("    {}: {}", k, v);
        }
    }

    if let Some(user_agent) = &schedule.user_agent {
        println!("  {} {}", "User Agent:".bold(), user_agent);
    }

    if let Some(proxy) = &schedule.proxy {
        println!("  {} {}", "Proxy:".bold(), proxy);
    }

    if let Some(timeout) = &schedule.timeout {
        println!("  {} {}", "Timeout:".bold(), format!("{}s", timeout));
    }

    if let Some(rate_limit) = &schedule.rate_limit {
        println!("  {} {}", "Rate Limit:".bold(), format!("{} req/s", rate_limit));
    }

    if let Some(max_redirects) = &schedule.max_redirects {
        println!("  {} {}", "Max Redirects:".bold(), max_redirects);
    }

    println!("  {} {}", "Follow Redirects:".bold(), schedule.follow_redirects.unwrap_or(true));
    println!("  {} {}", "TLS Verify:".bold(), !schedule.no_tls_verify);

    Ok(())
}

/// Run the scheduler daemon
async fn run_scheduler_daemon(ctx: Context, args: ScheduleDaemonArgs) -> Result<(), CliError> {
    println!("{} Starting scheduler daemon...", "🔄".green().bold());

    let storage = init_schedule_storage(&ctx).await?;

    // If --once flag is set, run scheduler once and exit
    if args.once {
        run_scheduler_iteration(&ctx, &storage).await?;
        println!("{} Scheduler ran once and exited", "✓".green().bold());
        return Ok(());
    }

    // Otherwise, run continuously
    let mut interval = tokio::time::interval(Duration::from_secs(30)); // Check every 30 seconds

    loop {
        interval.tick().await;
        if let Err(e) = run_scheduler_iteration(&ctx, &storage).await {
            eprintln!("{} Scheduler error: {}", "❌".red().bold(), e);
            // Continue running despite errors
        }
    }
}

/// Run one iteration of the scheduler
async fn run_scheduler_iteration(ctx: &Context, storage: &SqliteHistoryStorage) -> Result<(), CliError> {
    let now = chrono::Utc::now();

    // Get schedules that are due to run
    let mut conn = storage.conn().await;

    let mut stmt = conn.prepare(
        r#"
        SELECT id, name, target, profile, interval_minutes, checks, exclude_checks,
               headers, user_agent, proxy, timeout, rate_limit, max_redirects,
               follow_redirects, no_tls_verify, enabled, last_run, next_run
        FROM schedules
        WHERE enabled = 1 AND next_run <= ?1
        "#,
    )?;

    let rows = stmt.query_map(params![now.to_rfc3339().as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?, // id
            row.get::<_, String>(1)?, // name
            row.get::<_, String>(2)?, // target
            row.get::<_, String>(3)?, // profile
            row.get::<_, i64>(4)?,    // interval_minutes
            {
                let opt = row.get::<_, Option<String>>(5)?;
                match opt {
                    Some(s) if s == "null" => Vec::new(),
                    Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            {
                let opt = row.get::<_, Option<String>>(6)?;
                match opt {
                    Some(s) if s == "null" => Vec::new(),
                    Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            {
                let opt = row.get::<_, Option<String>>(7)?;
                match opt {
                    Some(s) if s == "null" => Vec::new(),
                    Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            row.get::<_, Option<String>>(8)?, // user_agent
            row.get::<_, Option<String>>(9)?, // proxy
            row.get::<_, Option<i64>>(10)?, // timeout
            row.get::<_, Option<f64>>(11)?, // rate_limit
            row.get::<_, Option<i64>>(12)?, // max_redirects
            row.get::<_, Option<i64>>(13)?, // follow_redirects
            row.get::<_, i64>(14)?, // no_tls_verify
            row.get::<_, i64>(15)?, // enabled
            row.get::<_, Option<String>>(16)?, // last_run
            row.get::<_, Option<String>>(17)?, // next_run
        ))
    })?;

    let mut schedules_to_run = Vec::new();
    for row in rows {
        let (id, name, target, profile, interval, checks, exclude, headers, user_agent, proxy, timeout, rate_limit, max_redirects, follow_redirects, no_tls_verify, enabled, last_run, next_run) = row?;
        schedules_to_run.push((
            id,
            name,
            target,
            profile,
            interval as u64,
            checks,
            exclude,
            headers,
            user_agent,
            proxy,
            timeout.map(|v| v as u64),
            rate_limit,
            max_redirects.map(|v| v as usize),
            follow_redirects.map(|v| v != 0),
            no_tls_verify != 0,
            enabled != 0,
            last_run.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
            next_run.map(|s| chrono::DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&chrono::Utc)),
        ));
    }


    // Run each scheduled scan
    for schedule in schedules_to_run {
        let (id, name, target, profile, interval, checks, exclude, headers, user_agent, proxy, timeout, rate_limit, max_redirects, follow_redirects, no_tls_verify, enabled, last_run, next_run) = schedule;

        if !enabled {
            continue; // Skip if somehow got disabled
        }

        println!("\n{} Running scheduled scan: {}", "⏰".blue().bold(), name);
        println!("  {} {}", "Target:".bold(), target);
        println!("  {} {}", "Scheduled for:".bold(), next_run.unwrap_or_else(|| now).to_rfc3339());
        println!("  {} {}", "Actual start:".bold(), now.to_rfc3339());

        // Update last_run and calculate next_run
        let mut guard = storage.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");

        let new_next_run = now + chrono::Duration::minutes(interval as i64);

        conn.execute(
            r#"
            UPDATE schedules SET
                last_run = ?1,
                next_run = ?2,
                updated_at = ?3
            WHERE id = ?4
            "#,
            params![
                now.to_rfc3339().as_str(),
                new_next_run.to_rfc3339().as_str(),
                now.to_rfc3339().as_str(),
                &id
            ]
        )?;


        // Run the scan
        let scan_result = run_scheduled_scan(ctx, &storage, &id, &target, profile, checks, exclude, headers, user_agent, proxy, timeout, rate_limit, max_redirects, follow_redirects, no_tls_verify).await?;

        // Record the run
        let mut guard = storage.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");

        conn.execute(
            r#"
            INSERT INTO schedule_runs (
                schedule_id, scan_id, start_time, end_time, status,
                findings_count, new_findings, fixed_findings
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
            )
            "#,
            params![
                &id,
                &scan_result.scan_id,
                &scan_result.start_time.to_rfc3339(),
                &scan_result.end_time.to_rfc3339(),
                &scan_result.status,
                scan_result.findings_count,
                scan_result.new_findings,
                scan_result.fixed_findings
            ]
        )?;


        // Show results
        println!("{} Scan completed: {}", "✓".green().bold(), name);
        println!("  {} {}", "Scan ID:".bold(), scan_result.scan_id);
        println!("  {} {}", "Duration:".bold(), format!("{:.2}s", scan_result.duration_secs));
        println!("  {} {}", "Findings:".bold(), scan_result.findings_count);
        if scan_result.new_findings > 0 {
            println!("  {} {}", "New Findings:".bold(), format!("{} {}", scan_result.new_findings, "🆕".green()));
        }
        if scan_result.fixed_findings > 0 {
            println!("  {} {}", "Fixed Findings:".bold(), format!("{} {}", scan_result.fixed_findings, "✅".yellow()));
        }
    }

    Ok(())
}

/// Run a scheduled scan and compare with baseline
async fn run_scheduled_scan(
    ctx: &Context,
    storage: &SqliteHistoryStorage,
    schedule_id: &str,
    target: &str,
    profile: ScanProfile,
    checks: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    headers: Option<Vec<(String, String)>>,
    user_agent: Option<String>,
    proxy: Option<String>,
    timeout: Option<u64>,
    rate_limit: Option<f64>,
    max_redirects: Option<usize>,
    follow_redirects: Option<bool>,
    no_tls_verify: bool,
) -> Result<ScheduleScanResult, CliError> {
    let start_time = chrono::Utc::now();
    let start_instant = std::time::Instant::now();

    // Get history storage for scan operations
    let history = get_history_storage(ctx);

    // Generate a unique scan ID for this run
    let scan_id = ScanId::new();

    // Get the most recent scan for this target to use as baseline
    let baseline_scan_id = get_baseline_scan_for_target(&storage, schedule_id, target).await?;

    // Run the actual scan
    let findings = perform_scan(
        target,
        profile,
        checks,
        exclude,
        headers,
        user_agent,
        proxy,
        timeout,
        rate_limit,
        max_redirects,
        follow_redirects,
        no_tls_verify,
    ).await?;

    let end_time = chrono::Utc::now();
    let duration = start_instant.elapsed();

    // Compare with baseline if we have one
    let (new_findings, fixed_findings) = if let Some(baseline_id) = baseline_scan_id {
        compare_with_baseline(&history, &baseline_id, &scan_id, &findings).await?
    } else {
        // No baseline yet, all findings are new
        (findings.len(), 0)
    };

    // Save this scan as the new baseline for future comparisons
    save_as_baseline(&storage, schedule_id, target, &scan_id).await?;

    Ok(ScheduleScanResult {
        schedule_id: schedule_id.to_string(),
        scan_id: scan_id.as_uuid().to_string(),
        start_time,
        end_time,
        status: "completed".to_string(),
        duration_secs: duration.as_secs_f64(),
        findings_count: findings.len(),
        new_findings,
        fixed_findings,
    })
}

/// Get the most recent scan for a target to use as baseline
async fn get_baseline_scan_for_target(
    storage: &SqliteHistoryStorage,
    schedule_id: &str,
    target: &str,
) -> Result<Option<ScanId>, CliError> {
    let mut conn = storage.conn().await;

    // Find the most recent successful scan for this target/schedule
    let result: Option<String> = conn.query_row(
        r#"
        SELECT sr.scan_id
        FROM schedule_runs sr
        JOIN schedules s ON sr.schedule_id = s.id
        WHERE s.id = ?1 AND sr.status = 'completed'
        ORDER BY sr.end_time DESC
        LIMIT 1
        "#,
        params![&schedule_id],
        |row| row.get(0),
    )?;


    if let Some(scan_id_str) = result {
        Ok(Some(ScanId::from_uuid(Uuid::parse_str(&scan_id_str)?)))
    } else {
        Ok(None)
    }
}

/// Perform an actual scan and return findings
async fn perform_scan(
    target: &str,
    profile: ScanProfile,
    checks: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    headers: Option<Vec<(String, String)>>,
    user_agent: Option<String>,
    proxy: Option<String>,
    timeout: Option<u64>,
    rate_limit: Option<f64>,
    max_redirects: Option<usize>,
    follow_redirects: Option<bool>,
    no_tls_verify: bool,
) -> Result<Vec<Finding>, CliError> {
    // Build scan target
    let mut target_obj =
        ScanTarget::new(target).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    target_obj = target_obj.with_timeout(timeout.unwrap_or(30)).with_max_redirects(max_redirects.unwrap_or(10));

    // Parse headers
    let mut header_vec = Vec::new();
    if let Some(header_list) = headers {
        for (k, v) in header_list {
            header_vec.push((k, v));
        }
    }

    if let Some(ua) = user_agent {
        target_obj = target_obj.with_user_agent(ua);
    }
    if let Some(proxy_url) = proxy {
        target_obj = target_obj.with_proxy(proxy_url);
    }
    if let Some(rate) = rate_limit {
        target_obj = target_obj.with_rate_limit(rate);
    }
    // Parse headers
    let mut header_vec = Vec::new();
    if let Some(header_list) = headers {
        for (k, v) in header_list {
            header_vec.push((k, v));
        }
    }

    if let Some(ua) = user_agent {
        target_obj = target_obj.with_user_agent(ua);
    }
    if let Some(proxy_url) = proxy {
        target_obj = target_obj.with_proxy(proxy_url);
    }
    if let Some(rate) = rate_limit {
        target_obj = target_obj.with_rate_limit(rate);
    }
    let follow = follow_redirects.unwrap_or(true);
    if follow {
        target_obj = target_obj.with_follow_redirects(true);
    }
    // Note: TLS verify is handled in build_client_with_config via tls_verify parameter

    // Prepare arguments for build_client_with_config
    let follow_redirects = follow_redirects.unwrap_or(true);
    let headers_opt = if header_vec.is_empty() { None } else { Some(header_vec) };
    let user_agent_str = user_agent.unwrap_or_default();
    let tls_verify = !no_tls_verify;

    // Get checks to run based on profile
    let all_checks = get_all_checks(&profile);

    let checks_to_run: Vec<openre_scan::checks::Check> = all_checks
        .into_iter()
        .filter(|check| {
            let should_run = checks.as_ref().map_or(true, |opt_checks| {
                opt_checks.iter().any(|s| s == check.name())
            });
            let should_exclude = exclude.as_ref().map_or(false, |opt_exclude| {
                opt_exclude.iter().any(|s| s == check.name())
            });
            should_run && !should_exclude
        })
        .collect();
    // If no checks specified, run all (excluding sensitive-files to match original behavior)
    let checks_to_run = if checks.is_none() && exclude.is_none() {
        get_all_checks(&profile)
            .into_iter()
            .filter(|c| c.name() != "sensitive-files")
            .collect()
    } else {
        checks_to_run
    };

    // Initialize findings vector
    let mut all_findings = Vec::new();
    let client = build_client_with_config(
        timeout.unwrap_or(30),
        max_redirects.unwrap_or(10),
        follow_redirects,
        user_agent_str,
        headers_opt,
        None, // proxy
        tls_verify,
    )?;

    // Process each check
    for check in checks_to_run {
        match check.run(&client, &target_obj.url).await {
            Ok(findings) => {
                if !findings.is_empty() {
                    all_findings.extend(findings);
                }
            }
            Err(e) => {
                // Log error but continue with other checks
                eprintln!("{} Check failed: {}", "⚠".yellow().bold(), e);
            }
        }
    }

    Ok(all_findings)
}

/// Compare current scan findings with baseline and return new/fixed counts
async fn compare_with_baseline(
    history: &SqliteHistoryStorage,
    baseline_scan_id: &ScanId,
    current_scan_id: &ScanId,
    current_findings: &[Finding],
) -> Result<(usize, usize), CliError> {
    // Get baseline findings
    let baseline_findings = history.get_deduplicated_findings(baseline_scan_id).await?;

    // Convert to sets for efficient comparison (using finding ID as key)
    let baseline_ids: HashSet<_> = baseline_findings.iter().map(|f| f.id).collect();
    let current_ids: HashSet<_> = current_findings.iter().map(|f| f.id).collect();

    // New findings: in current but not in baseline
    let new_findings = current_ids.difference(&baseline_ids).count();

    // Fixed findings: in baseline but not in current
    let fixed_findings = baseline_ids.difference(&current_ids).count();

    Ok((new_findings, fixed_findings))
}

/// Save a scan as the new baseline for future comparisons
async fn save_as_baseline(
    storage: &SqliteHistoryStorage,
    schedule_id: &str,
    target: &str,
    scan_id: &ScanId,
) -> Result<(), CliError> {
    // For now, we just rely on the schedule_runs table to track baseline
    // In a more sophisticated implementation, we might have a separate baselines table
    // or update a baseline_scan_id field in the schedules table

    // Update the schedule to record this scan as the baseline for next comparison
    let mut conn = storage.conn().await;

    // We could update a baseline_scan_id column here, but for simplicity
    // we'll just rely on the most recent completed run in schedule_runs

    Ok(())
}

/// Result of a scheduled scan
#[derive(Debug, Clone)]
struct ScheduleScanResult {
    schedule_id: String,
    scan_id: String,
    start_time: chrono::DateTime<chrono::Utc>,
    end_time: chrono::DateTime<chrono::Utc>,
    status: String,
    duration_secs: f64,
    findings_count: usize,
    new_findings: usize,
    fixed_findings: usize,
}

/// Helper struct for schedule listing
#[derive(tabled::Tabled)]
struct ScheduleListRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "TARGET")]
    target: String,
    #[tabled(rename = "PROFILE")]
    profile: String,
    #[tabled(rename = "INTERVAL")]
    interval: String,
    #[tabled(rename = "STATUS")]
    status: String,
    #[tabled(rename = "LAST RUN")]
    last_run: String,
    #[tabled(rename = "NEXT RUN")]
    next_run: String,
}