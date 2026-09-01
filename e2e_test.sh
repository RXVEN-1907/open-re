#!/bin/bash
# End-to-End CLI Testing Script for openre
# This script tests all openre CLI commands against a running API server
#
# Prerequisites:
# - API server running on http://localhost:8080
# - PostgreSQL, Redis, and MinIO running (via docker-compose)
# - openre CLI built with: cargo build --release --package openre-cli
#
# Usage:
#   ./e2e_test.sh [--skip-failing] [--verbose]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_URL="${OPENRE_API_URL:-http://localhost:8080}"
CLI_BIN="./target/release/openre"
SKIP_FAILING=false
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-failing)
            SKIP_FAILING=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Test tracking
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Helper functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_failure() { echo -e "${RED}[FAIL]${NC} $*"; }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

run_test() {
    local test_name="$1"
    local cmd="$2"
    local expected_exit="${3:-0}"

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if [[ "$VERBOSE" == "true" ]]; then
        log_info "Running: $test_name"
        log_info "Command: $cmd"
    fi

    if eval "$cmd" > /tmp/test_output.txt 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi

    if [[ $exit_code -eq $expected_exit ]]; then
        log_success "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_failure "$test_name (exit code: $exit_code, expected: $expected_exit)"
        if [[ "$VERBOSE" == "true" ]]; then
            cat /tmp/test_output.txt
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

run_test_json() {
    local test_name="$1"
    local cmd="$2"
    local jq_filter="${3:-.}"

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if [[ "$VERBOSE" == "true" ]]; then
        log_info "Running: $test_name"
        log_info "Command: $cmd"
    fi

    if eval "$cmd" > /tmp/test_output.txt 2>&1; then
        if echo "$(cat /tmp/test_output.txt)" | jq -e "$jq_filter" > /dev/null 2>&1; then
            log_success "$test_name"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        else
            log_failure "$test_name (JSON validation failed)"
            if [[ "$VERBOSE" == "true" ]]; then
                cat /tmp/test_output.txt
            fi
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    else
        log_failure "$test_name (command failed)"
        if [[ "$VERBOSE" == "true" ]]; then
            cat /tmp/test_output.txt
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ ! -f "$CLI_BIN" ]]; then
        log_failure "CLI binary not found at $CLI_BIN. Run 'cargo build --release --package openre-cli'"
        exit 1
    fi

    if ! curl -s "$API_URL/health" > /dev/null; then
        log_failure "API server not reachable at $API_URL"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Login and get API key
authenticate() {
    log_info "Authenticating..."

    # Try to register admin user first (might already exist)
    $CLI_BIN auth register \
        --email admin@example.com \
        --username admin \
        --password admin123 \
        --server "$API_URL" 2>/dev/null || true

    # Login
    local login_output
    login_output=$($CLI_BIN auth login \
        --email admin@example.com \
        --password admin123 \
        --server "$API_URL" 2>&1) || {
        log_failure "Login failed"
        echo "$login_output"
        exit 1
    }

    # Extract token from output or config
    export OPENRE_API_KEY=$($CLI_BIN auth token --server "$API_URL" 2>/dev/null)

    if [[ -z "$OPENRE_API_KEY" ]]; then
        log_failure "Failed to get API token"
        exit 1
    fi

    log_success "Authenticated successfully"
}

# ============ AUTH COMMANDS ============
test_auth_commands() {
    log_info "=== Testing Auth Commands ==="

    run_test "auth status" "$CLI_BIN auth status --server $API_URL"
    run_test "auth me" "$CLI_BIN auth me --server $API_URL"
    run_test "auth token" "$CLI_BIN auth token --server $API_URL"

    # API key management
    run_test "auth api-key list" "$CLI_BIN auth api-key list --server $API_URL"
    run_test_json "auth api-key create" "$CLI_BIN auth api-key create --name test-key --scopes read write --server $API_URL" '.api_key != null'

    # Note: logout clears tokens, so test last
    # run_test "auth logout" "$CLI_BIN auth logout --server $API_URL"
}

# ============ PROJECT COMMANDS ============
test_project_commands() {
    log_info "=== Testing Project Commands ==="

    local project_id=""

    run_test "project list" "$CLI_BIN project list --server $API_URL"
    run_test_json "project create" "$CLI_BIN project create test-project --description 'Test project for e2e' --server $API_URL" '.id != null'

    # Extract project ID from create output
    project_id=$($CLI_BIN project create test-project-2 --description 'Another test' --server "$API_URL" --format json 2>/dev/null | jq -r '.id')

    if [[ -n "$project_id" && "$project_id" != "null" ]]; then
        run_test "project get" "$CLI_BIN project get --id $project_id --server $API_URL"
        run_test "project update" "$CLI_BIN project update --id $project_id --name 'Updated Name' --server $API_URL"
        run_test "project collaborator list" "$CLI_BIN project collaborator list --project-id $project_id --server $API_URL"
        run_test "project invite list" "$CLI_BIN project invite list --project-id $project_id --server $API_URL"
        run_test "project share create" "$CLI_BIN project share create --project-id $project_id --permission view --server $API_URL"
        run_test "project export" "$CLI_BIN project export --id $project_id --format json --include-files false --include-analysis false --server $API_URL"

        # Delete last
        run_test "project delete" "$CLI_BIN project delete --id $project_id --force --server $API_URL"
    else
        log_skip "project get/update/delete (no project ID)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 5))
    fi
}

# ============ SCAN COMMANDS ============
test_scan_commands() {
    log_info "=== Testing Scan Commands ==="

    # First create a project for scans
    local project_id
    project_id=$($CLI_BIN project create scan-test-project --description 'Project for scan tests' --server "$API_URL" --format json 2>/dev/null | jq -r '.id')

    if [[ -z "$project_id" || "$project_id" == "null" ]]; then
        log_warn "Could not create project for scan tests, skipping scan tests"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 9))
        return
    fi

    local scan_id=""

    run_test "scan create" "$CLI_BIN scan create --project $project_id --target https://example.com --profile quick --name 'Test Scan' --server $API_URL"
    run_test "scan list" "$CLI_BIN scan list --project $project_id --server $API_URL"

    # Extract scan ID
    scan_id=$($CLI_BIN scan list --project "$project_id" --server "$API_URL" --format json 2>/dev/null | jq -r '.[0].id // empty')

    if [[ -n "$scan_id" && "$scan_id" != "null" ]]; then
        run_test "scan show" "$CLI_BIN scan show --id $scan_id --server $API_URL"
        run_test "scan status" "$CLI_BIN scan status --id $scan_id --interval 1 --server $API_URL" || true  # May fail if scan not running
        run_test "scan run" "$CLI_BIN scan run --id $scan_id --background --server $API_URL"
        run_test "scan cancel" "$CLI_BIN scan cancel --id $scan_id --server $API_URL"
        run_test "scan resume" "$CLI_BIN scan resume --id $scan_id --server $API_URL"
        run_test "scan export" "$CLI_BIN scan export --id $scan_id --format json --server $API_URL"
        run_test "scan delete" "$CLI_BIN scan delete --id $scan_id --force --server $API_URL"
    else
        log_skip "scan show/run/cancel/resume/export/delete (no scan ID)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 7))
    fi

    # Cleanup project
    $CLI_BIN project delete --id "$project_id" --force --server "$API_URL" 2>/dev/null || true
}

# ============ FINDING COMMANDS ============
test_finding_commands() {
    log_info "=== Testing Finding Commands ==="

    run_test "finding list" "$CLI_BIN finding list --server $API_URL"
    # Note: finding show requires a finding ID which we don't have
    log_skip "finding show (no finding ID)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

# ============ AI COMMANDS ============
test_ai_commands() {
    log_info "=== Testing AI Commands ==="

    run_test "ai providers" "$CLI_BIN ai providers --server $API_URL"
    run_test "ai templates" "$CLI_BIN ai templates --server $API_URL"
    run_test "ai chat" "$CLI_BIN ai chat --prompt 'Hello' --server $API_URL"
    run_test "ai analyze" "$CLI_BIN ai analyze --code 'fn main() {}' --server $API_URL"
    run_test "ai explain" "$CLI_BIN ai explain --code 'fn main() {}' --server $API_URL"
    run_test "ai remediate" "$CLI_BIN ai remediate --finding 'test finding' --server $API_URL"
    run_test "ai correlate" "$CLI_BIN ai correlate --findings '[]' --server $API_URL"
}

# ============ ANALYST COMMANDS ============
test_analyst_commands() {
    log_info "=== Testing Analyst Commands ==="

    run_test "analyst explain" "$CLI_BIN analyst explain --finding-id test --server $API_URL" || true
    run_test "analyst remediate" "$CLI_BIN analyst remediate --finding-id test --server $API_URL" || true
    run_test "analyst correlate" "$CLI_BIN analyst correlate --scan-id test --server $API_URL" || true
    run_test "analyst prioritize" "$CLI_BIN analyst prioritize --scan-id test --server $API_URL" || true
    run_test "analyst summarize" "$CLI_BIN analyst summarize --scan-id test --server $API_URL" || true
    run_test "analyst query" "$CLI_BIN analyst query --scan-id test --question 'test' --server $API_URL" || true
    run_test "analyst compare" "$CLI_BIN analyst compare --base-scan-id test --target-scan-id test --server $API_URL" || true
}

# ============ PLUGIN COMMANDS ============
test_plugin_commands() {
    log_info "=== Testing Plugin Commands ==="

    run_test "plugin list" "$CLI_BIN plugin list --server $API_URL"
    # plugin install/enable/disable/configure require specific plugins
    log_skip "plugin install/enable/disable/configure (require specific plugins)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 4))
}

# ============ REPORT COMMANDS ============
test_report_commands() {
    log_info "=== Testing Report Commands ==="

    run_test "report generate" "$CLI_BIN report generate --project test --format pdf --server $API_URL" || true
}

# ============ CONFIG COMMANDS ============
test_config_commands() {
    log_info "=== Testing Config Commands ==="

    run_test "config get" "$CLI_BIN config get --server $API_URL"
    run_test "config set" "$CLI_BIN config set --key test --value value --server $API_URL"
    run_test "config use" "$CLI_BIN config use --profile default --server $API_URL"
}

# ============ FILE COMMANDS ============
test_file_commands() {
    log_info "=== Testing File Commands ==="

    run_test "file list" "$CLI_BIN file list --server $API_URL"
    # file upload/download/delete require actual files
    log_skip "file upload/download/delete (require test files)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 3))
}

# ============ ANALYSIS COMMANDS ============
test_analysis_commands() {
    log_info "=== Testing Analysis Commands ==="

    run_test "analysis list" "$CLI_BIN analysis list --server $API_URL"
    # analysis commands require binary files
    log_skip "analysis create/show/cancel/retry (require binary files)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 4))
}

# ============ FUNCTION COMMANDS ============
test_function_commands() {
    log_info "=== Testing Function Commands ==="

    run_test "function list" "$CLI_BIN function list --server $API_URL"
    # function commands require analysis results
    log_skip "function show/pseudocode/cfg (require analysis results)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 3))
}

# ============ SERVER COMMANDS ============
test_server_commands() {
    log_info "=== Testing Server Commands ==="

    run_test "server status" "$CLI_BIN server status --server $API_URL"
    run_test "server version" "$CLI_BIN server version --server $API_URL"
}

# Main execution
main() {
    echo "========================================="
    echo "  openre CLI End-to-End Test Suite"
    echo "========================================="
    echo ""

    check_prerequisites
    authenticate

    echo ""
    log_info "Starting test suite..."
    echo ""

    test_auth_commands
    test_project_commands
    test_scan_commands
    test_finding_commands
    test_ai_commands
    test_analyst_commands
    test_plugin_commands
    test_report_commands
    test_config_commands
    test_file_commands
    test_analysis_commands
    test_function_commands
    test_server_commands

    echo ""
    echo "========================================="
    echo "  Test Summary"
    echo "========================================="
    echo -e "Total:    $TESTS_TOTAL"
    echo -e "${GREEN}Passed:   $TESTS_PASSED${NC}"
    echo -e "${RED}Failed:   $TESTS_FAILED${NC}"
    echo -e "${YELLOW}Skipped:  $TESTS_SKIPPED${NC}"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        log_failure "Some tests failed"
        exit 1
    else
        log_success "All tests passed (or skipped)"
        exit 0
    fi
}

main "$@"
