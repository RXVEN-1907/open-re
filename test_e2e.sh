#!/bin/bash
# End-to-End CLI Testing Script for openre
# This script tests all openre CLI commands against a running API server
#
# Usage:
#   1. Start the full stack: docker compose up -d
#   2. Wait for services: sleep 10
#   3. Run this script: ./test_e2e.sh
#
# Note: Some commands may fail due to API endpoints not being implemented yet.
# See E2E_TEST_REPORT.md for detailed status of each command.

set -e

# Configuration
API_URL="${OPENRE_API_URL:-http://localhost:8080}"
CLI_BIN="${OPENRE_CLI_BIN:-./target/release/openre}"
TEST_PROJECT_NAME="e2e-test-project"
TEST_PROJECT_DESC="E2E test project"
TARGET_URL="https://example.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
PASSED=0
FAILED=0
SKIPPED=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED++))
}

run_cli() {
    local cmd="$1"
    local expected_exit="${2:-0}"
    log_info "Running: $CLI_BIN $cmd"
    if $CLI_BIN $cmd; then
        if [ $expected_exit -eq 0 ]; then
            return 0
        else
            log_fail "Expected exit code $expected_exit but got 0"
            return 1
        fi
    else
        local exit_code=$?
        if [ $expected_exit -ne 0 ] && [ $exit_code -eq $expected_exit ]; then
            return 0
        else
            log_fail "Command failed with exit code $exit_code (expected $expected_exit)"
            return 1
        fi
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [ ! -f "$CLI_BIN" ]; then
        log_fail "CLI binary not found at $CLI_BIN. Run 'cargo build --release --package openre-cli' first."
        exit 1
    fi

    # Check API health
    log_info "Checking API health at $API_URL/health..."
    if curl -s -f "$API_URL/health" > /dev/null; then
        log_pass "API is healthy"
    else
        log_fail "API is not reachable at $API_URL. Make sure the server is running."
        exit 1
    fi
}

# Authenticate and get token
authenticate() {
    log_info "Authenticating..."

    # Try to register first (will fail if user exists)
    $CLI_BIN auth register --email "test@example.com" --username "testuser" --password "testpass123" --full-name "Test User" 2>/dev/null || true

    # Then login
    local output=$($CLI_BIN auth login --email "test@example.com" --password "testpass123" 2>&1)
    if echo "$output" | grep -q "Login successful"; then
        log_pass "Authentication successful"
        return 0
    else
        log_fail "Authentication failed: $output"
        return 1
    fi
}

# Test auth commands
test_auth() {
    log_info "=== Testing Auth Commands ==="

    # auth status
    if run_cli "auth status"; then
        log_pass "auth status"
    else
        log_fail "auth status"
    fi

    # auth me
    if run_cli "auth me"; then
        log_pass "auth me"
    else
        log_fail "auth me"
    fi

    # auth token
    if run_cli "auth token"; then
        log_pass "auth token"
    else
        log_fail "auth token"
    fi

    # auth api-key list
    if run_cli "auth api-key list"; then
        log_pass "auth api-key list"
    else
        log_fail "auth api-key list"
    fi

    # auth api-key create
    if run_cli "auth api-key create --name e2e-test-key --scopes read write"; then
        log_pass "auth api-key create"
    else
        log_fail "auth api-key create"
    fi

    # auth logout (will clear tokens, so re-authenticate after)
    if run_cli "auth logout"; then
        log_pass "auth logout"
        authenticate || return 1
    else
        log_fail "auth logout"
    fi
}

# Test project commands
test_projects() {
    log_info "=== Testing Project Commands ==="

    # project create - API returns NotImplemented
    if run_cli "project create $TEST_PROJECT_NAME --description \"$TEST_PROJECT_DESC\""; then
        log_pass "project create"
        PROJECT_ID=$($CLI_BIN project list --output json 2>/dev/null | jq -r '.projects[0].id' 2>/dev/null || echo "")
    else
        log_fail "project create (API not implemented)"
        PROJECT_ID=""
    fi

    # project list - API returns NotImplemented
    if run_cli "project list"; then
        log_pass "project list"
    else
        log_fail "project list (API not implemented)"
    fi

    if [ -n "$PROJECT_ID" ]; then
        # project get - API returns NotImplemented
        if run_cli "project get --id $PROJECT_ID"; then
            log_pass "project get"
        else
            log_fail "project get (API not implemented)"
        fi

        # project update - API returns NotImplemented
        if run_cli "project update --id $PROJECT_ID --name \"Updated $TEST_PROJECT_NAME\""; then
            log_pass "project update"
        else
            log_fail "project update (API not implemented)"
        fi

        # project export - API returns queued but not fully implemented
        if run_cli "project export --id $PROJECT_ID --format json --include-files --include-analysis"; then
            log_pass "project export"
        else
            log_fail "project export (partially implemented)"
        fi

        # project collaborator list - API returns NotImplemented
        if run_cli "project collaborator list --project-id $PROJECT_ID"; then
            log_pass "project collaborator list"
        else
            log_fail "project collaborator list (API not implemented)"
        fi

        # project invite list - API returns NotImplemented
        if run_cli "project invite list --project-id $PROJECT_ID"; then
            log_pass "project invite list"
        else
            log_fail "project invite list (API not implemented)"
        fi

        # project share create - partially implemented
        if run_cli "project share create --project-id $PROJECT_ID --permission view"; then
            log_pass "project share create"
        else
            log_fail "project share create (partially implemented)"
        fi

        # project delete - API returns NotImplemented
        if run_cli "project delete --id $PROJECT_ID --force"; then
            log_pass "project delete"
        else
            log_fail "project delete (API not implemented)"
        fi
    else
        log_skip "Project ID not available, skipping project detail commands"
        SKIPPED=$((SKIPPED + 7))
    fi
}

# Test scan commands
test_scans() {
    log_info "=== Testing Scan Commands ==="

    # Note: Scan commands use /api/scans/* but API doesn't have these endpoints
    # The API has /api/analysis for binary analysis and /api/security/findings for security findings

    if [ -n "$PROJECT_ID" ]; then
        # scan create - API endpoint doesn't exist
        if run_cli "scan create --project $PROJECT_ID --target $TARGET_URL --profile quick --name e2e-scan"; then
            log_pass "scan create"
            SCAN_ID=$($CLI_BIN scan list --project $PROJECT_ID --output json 2>/dev/null | jq -r '.scans[0].id' 2>/dev/null || echo "")
        else
            log_fail "scan create (API endpoint /api/scans not implemented)"
            SCAN_ID=""
        fi

        if [ -n "$SCAN_ID" ]; then
            # scan run
            if run_cli "scan run --id $SCAN_ID"; then
                log_pass "scan run"
            else
                log_fail "scan run (API endpoint not implemented)"
            fi

            # scan list
            if run_cli "scan list --project $PROJECT_ID"; then
                log_pass "scan list"
            else
                log_fail "scan list (API endpoint not implemented)"
            fi

            # scan show
            if run_cli "scan show --id $SCAN_ID"; then
                log_pass "scan show"
            else
                log_fail "scan show (API endpoint not implemented)"
            fi

            # scan status
            if run_cli "scan status --id $SCAN_ID --interval 1"; then
                log_pass "scan status"
            else
                log_fail "scan status (API endpoint not implemented)"
            fi

            # scan cancel
            if run_cli "scan cancel --id $SCAN_ID"; then
                log_pass "scan cancel"
            else
                log_fail "scan cancel (API endpoint not implemented)"
            fi

            # scan resume
            if run_cli "scan resume --id $SCAN_ID"; then
                log_pass "scan resume"
            else
                log_fail "scan resume (API endpoint not implemented)"
            fi

            # scan export
            if run_cli "scan export --id $SCAN_ID --format json"; then
                log_pass "scan export"
            else
                log_fail "scan export (API endpoint not implemented)"
            fi

            # scan delete
            if run_cli "scan delete --id $SCAN_ID --force"; then
                log_pass "scan delete"
            else
                log_fail "scan delete (API endpoint not implemented)"
            fi
        else
            log_skip "Scan ID not available, skipping scan detail commands"
            SKIPPED=$((SKIPPED + 8))
        fi
    else
        log_skip "Project ID not available, skipping scan commands"
        SKIPPED=$((SKIPPED + 10))
    fi
}

# Test finding commands
test_findings() {
    log_info "=== Testing Finding Commands ==="

    # Note: Finding commands use /api/findings/* but API has /api/security/findings

    if [ -n "$PROJECT_ID" ]; then
        # finding list - API endpoint mismatch (/api/findings vs /api/security/findings)
        if run_cli "finding list --project $PROJECT_ID"; then
            log_pass "finding list"
            FINDING_ID=$($CLI_BIN finding list --project $PROJECT_ID --output json 2>/dev/null | jq -r '.findings[0].id' 2>/dev/null || echo "")
        else
            log_fail "finding list (API endpoint mismatch: CLI expects /api/findings, API has /api/security/findings)"
            FINDING_ID=""
        fi

        if [ -n "$FINDING_ID" ]; then
            # finding show
            if run_cli "finding show --id $FINDING_ID --evidence --remediation"; then
                log_pass "finding show"
            else
                log_fail "finding show (API endpoint mismatch)"
            fi

            # finding verify
            if run_cli "finding verify --id $FINDING_ID --status true"; then
                log_pass "finding verify"
            else
                log_fail "finding verify (API endpoint mismatch)"
            fi

            # finding note
            if run_cli "finding note --id $FINDING_ID --text \"E2E test note\""; then
                log_pass "finding note"
            else
                log_fail "finding note (API endpoint mismatch)"
            fi
        else
            log_skip "Finding ID not available, skipping finding detail commands"
            SKIPPED=$((SKIPPED + 3))
        fi

        # finding export
        if run_cli "finding export --project $PROJECT_ID --format json"; then
            log_pass "finding export"
        else
            log_fail "finding export (API endpoint mismatch)"
        fi

        # finding stats
        if run_cli "finding stats --project $PROJECT_ID"; then
            log_pass "finding stats"
        else
            log_fail "finding stats (API endpoint mismatch)"
        fi

        # finding bulk
        if run_cli "finding bulk --project $PROJECT_ID --action verify"; then
            log_pass "finding bulk"
        else
            log_fail "finding bulk (API endpoint mismatch)"
        fi
    else
        log_skip "Project ID not available, skipping finding commands"
        SKIPPED=$((SKIPPED + 7))
    fi
}

# Test AI commands
test_ai() {
    log_info "=== Testing AI Commands ==="

    # ai chat - requires AI service configured
    if run_cli "ai chat --message \"Hello, how are you?\""; then
        log_pass "ai chat"
    else
        log_fail "ai chat (requires AI service configuration)"
    fi

    # ai providers
    if run_cli "ai providers"; then
        log_pass "ai providers"
    else
        log_fail "ai providers (requires AI service configuration)"
    fi

    # ai templates
    if run_cli "ai templates"; then
        log_pass "ai templates"
    else
        log_fail "ai templates (requires AI service configuration)"
    fi

    # ai analyze/explain/remediate/correlate - require finding ID
    log_skip "AI finding commands skipped (require finding ID and AI service)"
    SKIPPED=$((SKIPPED + 4))
}

# Test analyst commands
test_analyst() {
    log_info "=== Testing Analyst Commands ==="

    # All analyst commands require scan_id and finding_id, and AI analyst service
    log_skip "Analyst commands skipped (require scan/finding IDs and AI analyst service)"
    SKIPPED=$((SKIPPED + 7))
}

# Test plugin commands
test_plugins() {
    log_info "=== Testing Plugin Commands ==="

    # plugin list
    if run_cli "plugin list"; then
        log_pass "plugin list"
    else
        log_fail "plugin list"
    fi

    # plugin install/uninstall/enable/disable/configure - require plugin source
    log_skip "Plugin install/enable/disable/configure skipped (require plugin source)"
    SKIPPED=$((SKIPPED + 5))
}

# Test report commands
test_reports() {
    log_info "=== Testing Report Commands ==="

    if [ -n "$SCAN_ID" ]; then
        # report generate
        if run_cli "report generate --scan $SCAN_ID --format html"; then
            log_pass "report generate"
            REPORT_ID=$($CLI_BIN report list --project $PROJECT_ID --output json 2>/dev/null | jq -r '.reports[0].id' 2>/dev/null || echo "")
        else
            log_fail "report generate (requires scan ID)"
            REPORT_ID=""
        fi

        if [ -n "$REPORT_ID" ]; then
            # report list
            if run_cli "report list --project $PROJECT_ID"; then
                log_pass "report list"
            else
                log_fail "report list"
            fi

            # report show
            if run_cli "report show --id $REPORT_ID"; then
                log_pass "report show"
            else
                log_fail "report show"
            fi

            # report download
            if run_cli "report download --id $REPORT_ID --output /tmp/report.html"; then
                log_pass "report download"
            else
                log_fail "report download"
            fi

            # report delete
            if run_cli "report delete --id $REPORT_ID --force"; then
                log_pass "report delete"
            else
                log_fail "report delete"
            fi
        else
            log_skip "Report ID not available, skipping report detail commands"
            SKIPPED=$((SKIPPED + 4))
        fi
    else
        log_skip "Scan ID not available, skipping report commands"
        SKIPPED=$((SKIPPED + 5))
    fi

    # report templates
    if run_cli "report templates"; then
        log_pass "report templates"
    else
        log_fail "report templates"
    fi
}

# Test config commands
test_config() {
    log_info "=== Testing Config Commands ==="

    # config show
    if run_cli "config show"; then
        log_pass "config show"
    else
        log_fail "config show"
    fi

    # config get/set
    if run_cli "config set --key test.key --value test_value"; then
        log_pass "config set"
        if run_cli "config get --key test.key"; then
            log_pass "config get"
        else
            log_fail "config get"
        fi
    else
        log_fail "config set"
    fi

    # config list-profiles
    if run_cli "config list-profiles"; then
        log_pass "config list-profiles"
    else
        log_fail "config list-profiles"
    fi

    # config current-profile
    if run_cli "config current-profile"; then
        log_pass "config current-profile"
    else
        log_fail "config current-profile"
    fi

    # config path
    if run_cli "config path"; then
        log_pass "config path"
    else
        log_fail "config path"
    fi
}

# Test file commands
test_files() {
    log_info "=== Testing File Commands ==="

    # file list
    if run_cli "file list"; then
        log_pass "file list"
    else
        log_fail "file list"
    fi

    # file upload - requires a file
    log_skip "file upload/download/analyze skipped (requires test file)"
    SKIPPED=$((SKIPPED + 3))
}

# Test function commands
test_functions() {
    log_info "=== Testing Function Commands ==="

    # function list
    if run_cli "function list"; then
        log_pass "function list"
    else
        log_fail "function list"
    fi

    log_skip "Function detail commands skipped (require function ID)"
    SKIPPED=$((SKIPPED + 5))
}

# Test analysis commands (local binary analysis)
test_analysis() {
    log_info "=== Testing Analysis Commands (Local Binary) ==="

    # These are local commands that don't require API
    # analysis parse - requires a binary file
    log_skip "Analysis commands skipped (require binary file)"
    SKIPPED=$((SKIPPED + 15))
}

# Test server commands
test_server() {
    log_info "=== Testing Server Commands ==="

    # server status
    if run_cli "server status"; then
        log_pass "server status"
    else
        log_fail "server status"
    fi

    # server health
    if run_cli "server health"; then
        log_pass "server health"
    else
        log_fail "server health"
    fi

    # server info
    if run_cli "server info"; then
        log_pass "server info"
    else
        log_fail "server info"
    fi

    # server metrics
    if run_cli "server metrics"; then
        log_pass "server metrics"
    else
        log_fail "server metrics"
    fi

    log_skip "server start/stop skipped (require daemon management)"
    SKIPPED=$((SKIPPED + 2))
}

# Main test runner
main() {
    echo "========================================"
    echo "openre E2E CLI Test Suite"
    echo "========================================"
    echo "API URL: $API_URL"
    echo "CLI Binary: $CLI_BIN"
    echo ""

    check_prerequisites
    authenticate

    test_server
    test_config
    test_auth
    test_projects
    test_scans
    test_findings
    test_ai
    test_analyst
    test_plugins
    test_reports
    test_files
    test_functions
    test_analysis

    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
    echo ""

    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed. See E2E_TEST_REPORT.md for details.${NC}"
        exit 1
    else
        echo -e "${GREEN}All executed tests passed!${NC}"
        exit 0
    fi
}

# Run main
main "$@"
