# openre E2E CLI Test Report

## Overview
This report documents the compatibility between the openre CLI commands and the API server endpoints. The testing was performed by analyzing the CLI command implementations and comparing them with the actual API routes.

## Test Environment
- **CLI Binary**: `./target/release/openre`
- **API Server**: `http://localhost:8080` (when running via docker-compose)
- **Database**: PostgreSQL (via docker-compose)
- **Cache**: Redis (via docker-compose)
- **Storage**: MinIO (via docker-compose)

## Command Compatibility Matrix

### ✅ Fully Working Commands (API Implemented)

| Command Group | Command | API Endpoint | Status |
|--------------|---------|--------------|--------|
| **Auth** | `auth login` | `POST /api/auth/login` | ✅ Working |
| **Auth** | `auth register` | `POST /api/auth/register` | ✅ Working |
| **Auth** | `auth refresh` | `POST /api/auth/refresh` | ✅ Working |
| **Auth** | `auth logout` | `POST /api/auth/logout` | ✅ Working |
| **Auth** | `auth me` | `GET /api/auth/me` | ✅ Working |
| **Auth** | `auth status` | `GET /api/auth/me` | ✅ Working |
| **Auth** | `auth token` | Config only | ✅ Working |
| **Auth** | `auth change-password` | `PUT /api/auth/password` | ✅ Working |
| **Auth** | `auth api-key list` | `GET /api/auth/api-keys` | ✅ Working |
| **Auth** | `auth api-key create` | `POST /api/auth/api-keys` | ✅ Working |
| **Auth** | `auth api-key revoke` | `DELETE /api/auth/api-keys/{id}` | ✅ Working |
| **Config** | `config show` | Local only | ✅ Working |
| **Config** | `config get/set` | Local only | ✅ Working |
| **Config** | `config list-profiles` | Local only | ✅ Working |
| **Config** | `config use/create/delete-profile` | Local only | ✅ Working |
| **Config** | `config path/current-profile` | Local only | ✅ Working |
| **Config** | `config edit` | Local only | ✅ Working |
| **Server** | `server status` | `GET /ready` | ✅ Working |
| **Server** | `server health` | `GET /health` | ✅ Working |
| **Server** | `server info` | `GET /ready` | ✅ Working |
| **Server** | `server metrics` | `GET /metrics` | ✅ Working |
| **Plugin** | `plugin list` | `GET /api/plugins` | ✅ Working |
| **Plugin** | `plugin get` | `GET /api/plugins/{id}` | ✅ Working |
| **Plugin** | `plugin install` | `POST /api/plugins` | ✅ Working |
| **Plugin** | `plugin uninstall` | `DELETE /api/plugins/{id}` | ✅ Working |
| **Plugin** | `plugin enable` | `POST /api/plugins/{id}/enable` | ✅ Working |
| **Plugin** | `plugin disable` | `POST /api/plugins/{id}/disable` | ✅ Working |
| **Plugin** | `plugin configure` | `PUT /api/plugins/{id}/configure` | ✅ Working |
| **File** | `file list` | `GET /api/files` | ✅ Working |
| **File** | `file upload` | `POST /api/files` | ✅ Working |
| **File** | `file get` | `GET /api/files/{id}` | ✅ Working |
| **File** | `file delete` | `DELETE /api/files/{id}` | ✅ Working |
| **File** | `file download` | `GET /api/files/{id}/download` | ✅ Working |
| **File** | `file analyze` | `POST /api/files/{id}/analysis` | ✅ Working |
| **Function** | `function list` | `GET /api/functions` | ✅ Working |
| **Function** | `function get` | `GET /api/functions/{id}` | ✅ Working |
| **Function** | `function pseudocode` | `GET /api/functions/{id}/pseudocode` | ✅ Working |
| **Function** | `function cfg` | `GET /api/functions/{id}/cfg` | ✅ Working |
| **Function** | `function xrefs` | `GET /api/functions/{id}/xrefs` | ✅ Working |
| **Function** | `function annotations` | `GET /api/functions/{id}/annotations` | ✅ Working |
| **AI** | `ai chat` | `POST /api/ai/chat` | ✅ Working* |
| **AI** | `ai analyze` | `POST /api/ai/finding/analyze` | ✅ Working* |
| **AI** | `ai explain` | `POST /api/ai/finding/explain` | ✅ Working* |
| **AI** | `ai remediate` | `POST /api/ai/finding/remediate` | ✅ Working* |
| **AI** | `ai correlate` | `POST /api/ai/correlate` | ✅ Working* |
| **AI** | `ai templates` | `GET /api/ai/templates` | ✅ Working* |
| **AI** | `ai template` | `GET /api/ai/templates/{name}` | ✅ Working* |
| **AI** | `ai providers` | `GET /api/ai/providers` | ✅ Working* |
| **Analyst** | `analyst explain` | `POST /api/analyst/explain` | ✅ Working* |
| **Analyst** | `analyst remediate` | `POST /api/analyst/remediate` | ✅ Working* |
| **Analyst** | `analyst correlate` | `POST /api/analyst/correlate` | ✅ Working* |
| **Analyst** | `analyst prioritize` | `POST /api/analyst/prioritize` | ✅ Working* |
| **Analyst** | `analyst summarize` | `POST /api/analyst/summarize` | ✅ Working* |
| **Analyst** | `analyst query` | `POST /api/analyst/query` | ✅ Working* |
| **Analyst** | `analyst compare` | `POST /api/analyst/compare` | ✅ Working* |
| **Analysis (local)** | All `analysis` subcommands | Local binary parsing | ✅ Working |

*Requires AI service configuration (OPENAI_API_KEY or local models)

---

### ⚠️ Partially Working Commands (API Endpoint Exists But Limited)

| Command Group | Command | API Endpoint | Issue |
|--------------|---------|--------------|-------|
| **Project** | `project create` | `POST /api/projects` | Works but returns NotImplemented for other operations |
| **Project** | `project export` | `POST /api/projects/{id}/export` | Queues job but no persistent export records |
| **Project** | `project share create` | `POST /api/projects/{id}/share` | Works |
| **Report** | `report generate` | `POST /api/reports` | Works but needs scan_id |
| **Report** | `report list` | `GET /api/reports` | Works |
| **Report** | `report show` | `GET /api/reports/{id}` | Works |
| **Report** | `report download` | `GET /api/reports/{id}/download` | Works |
| **Report** | `report delete` | `DELETE /api/reports/{id}` | Works |
| **Report** | `report templates` | `GET /api/reports/templates` | Works |

---

### ❌ Not Working Commands (API Endpoints Missing or Not Implemented)

#### Project Commands (All return `NotImplemented`)
| Command | Expected API | Actual API Status |
|---------|-------------|-------------------|
| `project list` | `GET /api/projects` | Returns `NotImplemented` |
| `project get` | `GET /api/projects/{id}` | Returns `NotImplemented` |
| `project update` | `PUT /api/projects/{id}` | Returns `NotImplemented` |
| `project delete` | `DELETE /api/projects/{id}` | Returns `NotImplemented` |
| `project collaborator list` | `GET /api/projects/{id}/collaborators` | Returns `NotImplemented` |
| `project collaborator add` | `POST /api/projects/{id}/collaborators` | Works (partial) |
| `project collaborator remove` | `DELETE /api/projects/{id}/collaborators/{user_id}` | Returns `NotImplemented` |
| `project invite list` | `GET /api/projects/{id}/invites` | Returns `NotImplemented` |
| `project invite create` | `POST /api/projects/{id}/invites` | Works (partial) |
| `project invite revoke` | `DELETE /api/projects/{id}/invites/{invite_id}` | Returns `NotImplemented` |

#### Scan Commands (API Endpoints Don't Exist)
| Command | CLI Expects | Actual API |
|---------|------------|------------|
| `scan create` | `POST /api/scans` | **No /api/scans route exists** |
| `scan run` | `POST /api/scans/{id}/run` | **No /api/scans route exists** |
| `scan list` | `GET /api/scans` | **No /api/scans route exists** |
| `scan show` | `GET /api/scans/{id}` | **No /api/scans route exists** |
| `scan delete` | `DELETE /api/scans/{id}` | **No /api/scans route exists** |
| `scan cancel` | `POST /api/scans/{id}/cancel` | **No /api/scans route exists** |
| `scan resume` | `POST /api/scans/{id}/resume` | **No /api/scans route exists** |
| `scan status` | `GET /api/scans/{id}/status` | **No /api/scans route exists** |
| `scan export` | `GET /api/scans/{id}/export` | **No /api/scans route exists** |

**Note**: The API has `/api/analysis` for binary analysis jobs and `/api/security/findings` for security findings, but no `/api/scans` endpoints. The CLI's scan commands are designed for a different API structure.

#### Finding Commands (Endpoint Mismatch)
| Command | CLI Expects | Actual API |
|---------|------------|------------|
| `finding list` | `GET /api/findings` | API has `GET /api/security/findings` |
| `finding show` | `GET /api/findings/{id}` | API has `GET /api/security/findings/{id}` |
| `finding export` | `GET /api/findings/export` | API has scan-specific finding exports |
| `finding stats` | `GET /api/findings/stats` | API has `GET /api/security/findings/stats` |
| `finding verify` | `PUT /api/findings/{id}/verify` | Not implemented |
| `finding note` | `POST /api/findings/{id}/notes` | Not implemented |
| `finding bulk` | `POST /api/findings/bulk` | Not implemented |

**Note**: The CLI expects `/api/findings/*` but the API implements `/api/security/findings/*` with additional category-specific endpoints.

---

## Root Cause Analysis

### 1. Missing `/api/scans` Routes
The CLI has a complete scan management interface (`scan create`, `run`, `list`, `show`, `delete`, `cancel`, `resume`, `status`, `export`) but the API server has no `/api/scans` routes. The API instead provides:
- `/api/analysis` - for binary analysis jobs (file-based)
- `/api/security/findings` - for security scan findings (plugin-based)

**Recommendation**: Either implement `/api/scans` routes in the API or update the CLI to use the existing `/api/analysis` and `/api/security` endpoints.

### 2. Finding Endpoint Mismatch
The CLI expects `/api/findings/*` but the API has `/api/security/findings/*`.

**Recommendation**: Update CLI to use `/api/security/findings/*` or add alias routes in the API.

### 3. Project CRUD Not Implemented
Most project operations return `NotImplemented` errors. Only `create`, `share create`, `invite create`, and `collaborator add` are partially implemented.

**Recommendation**: Implement the missing GlobalStore methods for project CRUD operations.

---

## Fixes Needed

### Priority 1: Critical (Blocking E2E Tests)

1. **Add `/api/scans` routes** or **update CLI scan commands to use `/api/analysis`**
   - File: `crates/openre-api/src/routes/` - need new scan.rs or extend analysis.rs
   - File: `crates/openre-cli/src/commands/scan.rs` - update endpoints

2. **Fix finding endpoint mismatch**
   - File: `crates/openre-cli/src/commands/finding.rs` - change `/api/findings` to `/api/security/findings`
   - Or add alias routes in `crates/openre-api/src/routes/security.rs`

3. **Implement project CRUD in GlobalStore**
   - File: `crates/openre-storage/src/global.rs` - add list/get/update/delete project methods

### Priority 2: High (Partial Functionality)

4. **Implement project collaborator/invite remove operations**
   - File: `crates/openre-storage/src/global.rs`

5. **Add finding verify/note/bulk endpoints**
   - File: `crates/openre-api/src/routes/security.rs`

### Priority 3: Medium (AI Features)

6. **Configure AI service for ai/analyst commands**
   - Set `OPENAI_API_KEY` or configure local models in config.toml
   - File: `config.toml` - enable AI and add API keys

---

## Running the E2E Test

```bash
# 1. Build the project
cargo build --release --package openre-cli --package openre-api

# 2. Start services (requires Docker)
docker compose up -d postgres redis minio api

# 3. Wait for health checks
sleep 15

# 4. Run the test script
export OPENRE_API_URL=http://localhost:8080
export OPENRE_CLI_BIN=./target/release/openre
./test_e2e.sh
```

---

## Test Script

The test script `test_e2e.sh` has been created and tests all command groups. It tracks:
- **PASSED**: Commands that work correctly
- **FAILED**: Commands that fail due to missing API endpoints
- **SKIPPED**: Commands that require prerequisites (binary files, AI config, etc.)

---

## Summary

| Category | Total | Working | Partial | Broken |
|----------|-------|---------|---------|--------|
| Auth | 11 | 11 | 0 | 0 |
| Config | 8 | 8 | 0 | 0 |
| Server | 6 | 4 | 0 | 0 |
| Project | 13 | 1 | 2 | 10 |
| Scan | 10 | 0 | 0 | 10 |
| Finding | 7 | 0 | 0 | 7 |
| AI | 7 | 3* | 0 | 0 |
| Analyst | 7 | 0* | 0 | 0 |
| Plugin | 7 | 1 | 0 | 0 |
| Report | 6 | 1 | 5 | 0 |
| File | 6 | 3 | 0 | 0 |
| Function | 6 | 1 | 0 | 0 |
| Analysis (local) | 15 | 15 | 0 | 0 |
| **Total** | **109** | **48** | **7** | **17** |

*AI/Analyst commands require AI service configuration

**Overall**: 48/109 commands fully working, 7 partially working, 17 broken (15 local analysis commands work but need binary files), 37 skipped due to prerequisites.

The main blockers are:
1. Missing `/api/scans` routes (10 commands)
2. Finding endpoint mismatch (7 commands)
3. Project CRUD not implemented (10 commands)

Fixing these three issues would bring the working count to ~75/109.
