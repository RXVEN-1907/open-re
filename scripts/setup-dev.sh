#!/usr/bin/env bash
# setup-dev.sh - Development environment setup for open-re
# This script installs all necessary tools and configures the development environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
MINIMAL_MODE=false
SKIP_RUST=false
SKIP_NODE=false
SKIP_DOCKER=false
SKIP_HOOKS=false

# Print functions
print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚══╝     ╚══════╝╚══════╝         ╚═╝  ╚═╝╚══════╝

Open-source Reverse Engineering & Offensive Security Platform
EOF
    echo -e "${NC}"
    echo -e "${BOLD}Development Environment Setup${NC}"
    echo
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if command_exists apt-get; then
            PKG_MGR="apt"
        elif command_exists dnf; then
            PKG_MGR="dnf"
        elif command_exists pacman; then
            PKG_MGR="pacman"
        elif command_exists zypper; then
            PKG_MGR="zypper"
        else
            PKG_MGR="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MGR="brew"
    else
        OS="unknown"
        PKG_MGR="unknown"
    fi
    print_info "Detected OS: $OS ($PKG_MGR)"
}

# Install Rust toolchain
install_rust() {
    if command_exists rustc && command_exists cargo; then
        print_success "Rust already installed: $(rustc --version)"
        return 0
    fi

    print_step "Installing Rust toolchain..."
    if [[ "$PKG_MGR" == "apt" ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    elif [[ "$PKG_MGR" == "brew" ]]; then
        brew install rust
    else
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi

    # Verify installation
    if command_exists rustc && command_exists cargo; then
        print_success "Rust installed: $(rustc --version)"
    else
        print_error "Failed to install Rust"
        return 1
    fi
}

# Install cargo tools
install_cargo_tools() {
    print_step "Installing cargo development tools..."

    local tools=(
        "cargo-audit"
        "cargo-deny"
        "cargo-llvm-cov"
        "cargo-nextest"
        "cargo-make"
        "cargo-outdated"
        "cargo-tree"
        "cargo-watch"
    )

    for tool in "${tools[@]}"; do
        if cargo install --list | grep -q "^$tool "; then
            print_info "$tool already installed"
        else
            print_info "Installing $tool..."
            cargo install "$tool" --locked || print_warning "Failed to install $tool"
        fi
    done

    print_success "Cargo tools installation complete"
}

# Install Node.js and npm
install_node() {
    if command_exists node && command_exists npm; then
        print_success "Node.js already installed: $(node --version)"
        return 0
    fi

    print_step "Installing Node.js..."

    if [[ "$PKG_MGR" == "apt" ]]; then
        # Install Node.js 20 LTS
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [[ "$PKG_MGR" == "brew" ]]; then
        brew install node@20
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        sudo dnf module install -y nodejs:20
    else
        print_warning "Please install Node.js 20+ manually for your platform"
        return 1
    fi

    # Install global npm packages
    if command_exists npm; then
        print_info "Installing global npm packages..."
        npm install -g markdownlint-cli cspell @typescript-eslint/parser @typescript-eslint/eslint-plugin || print_warning "Some npm packages failed to install"
    fi

    if command_exists node; then
        print_success "Node.js installed: $(node --version)"
    else
        print_error "Failed to install Node.js"
        return 1
    fi
}

# Install Docker
install_docker() {
    if command_exists docker && command_exists docker-compose; then
        print_success "Docker already installed: $(docker --version)"
        return 0
    fi

    print_step "Installing Docker..."

    if [[ "$PKG_MGR" == "apt" ]]; then
        # Install Docker
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER"
        # Install docker-compose plugin
        sudo apt-get update && sudo apt-get install -y docker-compose-plugin
    elif [[ "$PKG_MGR" == "brew" ]]; then
        brew install docker docker-compose
        # Start Docker Desktop on macOS
        if [[ ! -f /Applications/Docker.app/Contents/MacOS/Docker ]]; then
            print_warning "Please install Docker Desktop from https://www.docker.com/products/docker-desktop"
        fi
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        sudo dnf install -y docker docker-compose
        sudo systemctl enable --now docker
        sudo usermod -aG docker "$USER"
    else
        print_warning "Please install Docker manually for your platform"
        return 1
    fi

    if command_exists docker; then
        print_success "Docker installed: $(docker --version)"
    else
        print_error "Failed to install Docker"
        return 1
    fi
}

# Setup pre-commit hooks
setup_precommit_hooks() {
    print_step "Setting up pre-commit hooks..."

    if [[ ! -f .pre-commit-config.yaml ]]; then
        print_info "Creating .pre-commit-config.yaml..."
        cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/rust-lang/rustfmt
    rev: stable
    hooks:
      - id: rustfmt
        name: Format Rust code
        entry: cargo fmt --all -- --check
        language: system
        types: [rust]
        args: ["--check"]

  - repo: https://github.com/rust-lang/rust-clippy
    rev: stable
    hooks:
      - id: clippy
        name: Clippy lints
        entry: cargo clippy --all-targets --all-features -- -D warnings
        language: system
        types: [rust]
        args: ["--all-targets", "--all-features", "--", "-D", "warnings"]

  - repo: https://github.com/igorshubovych/markdownlint-cli
    rev: v0.39.0
    hooks:
      - id: markdownlint
        name: Markdown linting
        entry: markdownlint-cli
        language: node
        types: [markdown]
        args: ["--config", ".markdownlint.json"]

  - repo: https://github.com/crate-ci/cargo-audit
    rev: v0.21.0
    hooks:
      - id: cargo-audit
        name: Security audit
        entry: cargo audit
        language: system
        types: [rust]

  - repo: https://github.com/EmbarkStudios/cargo-deny
    rev: 0.14.13
    hooks:
      - id: cargo-deny
        name: Dependency checks
        entry: cargo deny check
        language: system
        types: [rust]
        args: ["check", "advisories", "bans", "licenses", "sources"]
EOF
    fi

    # Install pre-commit if not available
    if ! command_exists pre-commit; then
        if command_exists pip3; then
            pip3 install pre-commit
        elif command_exists pip; then
            pip install pre-commit
        else
            print_warning "Please install pre-commit manually: pip install pre-commit"
            return 1
        fi
    fi

    # Install hooks
    pre-commit install
    pre-commit install --hook-type commit-msg

    print_success "Pre-commit hooks installed"
}

# Create development config files
create_dev_configs() {
    print_step "Creating development configuration files..."

    # Create .markdownlint.json if not exists
    if [[ ! -f .markdownlint.json ]]; then
        cat > .markdownlint.json << 'EOF'
{
  "default": true,
  "MD013": { "line_length": 120, "code_blocks": false, "tables": false },
  "MD024": { "siblings_only": true },
  "MD033": false,
  "MD041": false,
  "MD029": { "style": "ordered" }
}
EOF
        print_success "Created .markdownlint.json"
    fi

    # Create .cspell.json if not exists
    if [[ ! -f .cspell.json ]]; then
        cat > .cspell.json << 'EOF'
{
  "version": "0.2",
  "language": "en",
  "words": [
    "openre",
    "openre-scan",
    "openre-cli",
    "ratatui",
    "crossterm",
    "serde",
    "tokio",
    "reqwest",
    "clap",
    "anyhow",
    "thiserror",
    "chrono",
    "uuid",
    "sqlx",
    "axum",
    "tonic",
    "prost",
    "goblin",
    "wasmtime",
    "wasmparser",
    "toml",
    "yaml",
    "json",
    "sarif",
    "pwned",
    "exploit",
    "vuln",
    "fingerprint",
    "mitre",
    "capec",
    "cwe",
    "owasp",
    "hsts",
    "csp",
    "cors",
    "coop",
    "corp",
    "xss",
    "sqli",
    "csrf",
    "jwt",
    "grpc",
    "protobuf",
    "ws",
    "tls",
    "ssl",
    "pki",
    "ca",
    "san",
    "dns",
    "http",
    "https",
    "url",
    "uri",
    "api",
    "cli",
    "tui",
    "ui",
    "wasm",
    "elf",
    "pe",
    "macho",
    "disassembly",
    "decompilation",
    "cfg",
    "dfa",
    "ast",
    "ir",
    "jit",
    "aot",
    "llvm",
    "cranelift",
    "wat",
    "wasi",
    "syscalls",
    "seccomp",
    "capabilities",
    "sandbox",
    "fuel",
    "metering"
  ],
  "ignorePaths": [
    "target",
    ".git",
    "node_modules",
    "*.lock",
    "*.sum",
    "Cargo.lock"
  ]
}
EOF
        print_success "Created .cspell.json"
    fi

    # Create rustfmt.toml if not exists
    if [[ ! -f rustfmt.toml ]]; then
        cat > rustfmt.toml << 'EOF'
edition = "2021"
max_width = 100
tab_spaces = 4
hard_tabs = false
newline_style = "Unix"
use_small_heuristics = "Max"
fn_single_line = false
fn_args_layout = "Tall"
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
reorder_imports = true
format_strings = true
format_code_in_doc_comments = true
doc_comment_line_length = 100
EOF
        print_success "Created rustfmt.toml"
    fi

    # Create clippy.toml if not exists
    if [[ ! -f clippy.toml ]]; then
        cat > clippy.toml << 'EOF'
[lints]
rust_2021_idioms = "warn"
clippy::all = "warn"
clippy::pedantic = "warn"
clippy::nursery = "warn"
clippy::cargo = "warn"
clippy::restriction = "off"

# Allow some common patterns in this codebase
clippy::module_name_repetitions = "allow"
clippy::missing_errors_doc = "allow"
clippy::missing_panics_doc = "allow"
clippy::must_use_candidate = "allow"
clippy::too_many_arguments = "allow"
clippy::struct_excessive_bools = "allow"
clippy::enum_variant_names = "allow"
clippy::similar_names = "allow"
clippy::wildcard_imports = "allow"
clippy::multiple_crate_versions = "allow"
EOF
        print_success "Created clippy.toml"
    fi
}

# Build core crates
build_core_crates() {
    print_step "Building core crates in release mode..."

    local core_crates=(
        "openre-core"
        "openre-config"
        "openre-telemetry"
        "openre-storage"
        "openre-queue"
        "openre-intelligence"
    )

    for crate in "${core_crates[@]}"; do
        print_info "Building $crate..."
        cargo build --release --package "$crate" || print_warning "Failed to build $crate"
    done

    # Build the scanner
    print_info "Building openre-scan..."
    cargo build --release --package openre-scan || print_warning "Failed to build openre-scan"

    print_success "Core crates built"
}

# Run tests
run_tests() {
    print_step "Running tests..."

    # Run tests for core crates
    cargo test --package openre-core --package openre-config --package openre-telemetry --package openre-storage --package openre-queue --package openre-intelligence --lib || print_warning "Some tests failed"

    print_success "Tests completed"
}

# Print next steps
print_next_steps() {
    echo
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  Setup Complete! Next Steps:${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "  ${BOLD}1.${NC} Restart your shell or run: ${CYAN}source ~/.cargo/env${NC}"
    echo -e "  ${BOLD}2.${NC} Run the scanner: ${CYAN}./target/release/openre-scan scan https://example.com --profile quick${NC}"
    echo -e "  ${BOLD}3.${NC} Launch the TUI: ${CYAN}./target/release/openre-scan tui${NC}"
    echo -e "  ${BOLD}4.${NC} Run all tests: ${CYAN}cargo test --workspace${NC}"
    echo -e "  ${BOLD}5.${NC} Check formatting: ${CYAN}cargo fmt --all -- --check${NC}"
    echo -e "  ${BOLD}6.${NC} Run linters: ${CYAN}cargo clippy --workspace --all-targets --all-features -- -D warnings${NC}"
    echo
    echo -e "  ${BOLD}Documentation:${NC}"
    echo -e "  • Architecture docs: ${CYAN}docs/architecture/${NC}"
    echo -e "  • Plugin development: ${CYAN}docs/injection/plugin_development_guide.md${NC}"
    echo -e "  • Contributing guide: ${CYAN}CONTRIBUTING.md${NC}"
    echo
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "  • Watch for changes: ${CYAN}cargo watch -x 'test --workspace'${NC}"
    echo -e "  • Run specific crate tests: ${CYAN}cargo test -p openre-scan${NC}"
    echo -e "  • Generate docs: ${CYAN}cargo doc --workspace --no-deps --open${NC}"
    echo
}

# Show usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Setup development environment for open-re platform.

Options:
  --minimal         Minimal setup (Rust only, no Docker/Node)
  --skip-rust       Skip Rust installation
  --skip-node       Skip Node.js installation
  --skip-docker     Skip Docker installation
  --skip-hooks      Skip pre-commit hooks setup
  -h, --help        Show this help message

Examples:
  $0                    # Full setup
  $0 --minimal          # Minimal setup for CI
  $0 --skip-docker      # Skip Docker (if already installed)
EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --minimal)
                MINIMAL_MODE=true
                shift
                ;;
            --skip-rust)
                SKIP_RUST=true
                shift
                ;;
            --skip-node)
                SKIP_NODE=true
                shift
                ;;
            --skip-docker)
                SKIP_DOCKER=true
                shift
                ;;
            --skip-hooks)
                SKIP_HOOKS=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main function
main() {
    print_banner
    parse_args "$@"

    print_info "Starting open-re development environment setup..."
    echo

    detect_os

    # Check if we're in the right directory
    if [[ ! -f Cargo.toml ]] || [[ ! -d crates ]]; then
        print_error "Please run this script from the open-re repository root"
        exit 1
    fi

    # Install Rust
    if [[ "$SKIP_RUST" != "true" ]]; then
        install_rust
    else
        print_info "Skipping Rust installation"
    fi

    # Install cargo tools
    if [[ "$MINIMAL_MODE" != "true" ]]; then
        install_cargo_tools
    fi

    # Install Node.js
    if [[ "$SKIP_NODE" != "true" && "$MINIMAL_MODE" != "true" ]]; then
        install_node
    else
        print_info "Skipping Node.js installation"
    fi

    # Install Docker
    if [[ "$SKIP_DOCKER" != "true" && "$MINIMAL_MODE" != "true" ]]; then
        install_docker
    else
        print_info "Skipping Docker installation"
    fi

    # Setup pre-commit hooks
    if [[ "$SKIP_HOOKS" != "true" && "$MINIMAL_MODE" != "true" ]]; then
        setup_precommit_hooks
    else
        print_info "Skipping pre-commit hooks setup"
    fi

    # Create dev configs
    create_dev_configs

    # Build core crates
    if [[ "$MINIMAL_MODE" != "true" ]]; then
        build_core_crates
    fi

    # Run tests
    if [[ "$MINIMAL_MODE" != "true" ]]; then
        run_tests
    fi

    print_next_steps
}

# Run main
main "$@"