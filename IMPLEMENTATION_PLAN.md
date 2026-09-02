# Phase 25: Concurrent Jobs & Background Job Manager - Implementation Plan

## Overview
Implement a real job manager with cancellation, retry, status, logs using openre-queue (Redis Streams) and openre-storage.

## Architecture

### 1. New Files to Create
- `crates/openre-queue/src/job_manager.rs` - BackgroundJobManager implementation
- `crates/openre-queue/src/workflow.rs` - Workflow/Pipeline system
- `crates/openre-queue/src/logs.rs` - Job logging infrastructure
- `crates/openre-cli/src/commands/job.rs` - CLI commands for job management

### 2. Files to Modify
- `crates/openre-queue/src/lib.rs` - Export new modules
- `crates/openre-queue/src/job.rs` - Extend Job struct with dependencies, logs
- `crates/openre-queue/src/queue_manager.rs` - Add retry_job, get_job_logs methods
- `crates/openre-cli/src/commands/mod.rs` - Add job module
- `crates/openre-cli/src/main.rs` - Register JobCommands

## Implementation Details

### Job Struct Extensions
- Add `dependencies: Vec<JobId>` for workflow dependency graph
- Add `logs: Vec<LogEntry>` for job logs
- Add `LogEntry` struct with timestamp, level, message

### BackgroundJobManager
- `job_queue: Arc<QueueManager>`
- `running_jobs: Arc<DashMap<JobId, JobHandle>>`
- `job_storage: Arc<dyn JobStorage>` (using openre-storage patterns)
- `config: JobManagerConfig`
- Methods: start_job, cancel_job, pause_job, resume_job, get_job_status, get_job_logs, list_jobs, wait_for_job

### JobQueue (extend QueueManager)
- `enqueue_job(job: Job) -> JobId`
- `dequeue_job() -> Option<Job>`
- `cancel_job(job_id: JobId) -> Result<()>`
- `retry_job(job_id: JobId) -> Result<()>`
- `get_job_status(job_id: JobId) -> JobStatus`
- `get_job_logs(job_id: JobId) -> Vec<LogEntry>`

### Workflow/Pipeline System
- Define standard security analysis pipeline:
  `binary -> identify -> disassemble -> detect_suspicious -> ai_analysis -> security_finding -> remediation -> verification`
- Each step is a job with dependencies on previous jobs
- Workflow manager to orchestrate multi-job pipelines

### CLI Commands
- `openre job list` - List jobs with filters
- `openre job start <type>` - Start a new job
- `openre job cancel <id>` - Cancel a job
- `openre job status <id>` - Get job status
- `openre job logs <id> [--follow]` - Get job logs with optional follow
- `openre job retry <id>` - Retry a failed job
- `openre job workflow start <pipeline>` - Start a workflow

## Dependencies
- openre-queue (existing)
- openre-storage (for job persistence)
- openre-core (JobType, IDs)
- openre-config (configuration)
- openre-telemetry (metrics)
- dashmap (for running_jobs)
- tokio-stream (for log streaming)
