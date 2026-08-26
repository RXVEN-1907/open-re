# Sentinel Security Scanner

A lightweight TUI security assessment tool built from the open-re project.

## 🚀 Quick Start

### Build from source

```bash
./build.sh
```

### Run a scan

```bash
./run.sh scan https://example.com
```

### Show help

```bash
./run.sh --help
```

## 📋 Features

-   **Lightweight**: Minimal dependencies, fast execution
-   **Intelligent Analysis**: Correlation engine, CVE matching, dependency analysis
-   **Multiple Profiles**: Quick, standard, and full scan profiles
-   **Flexible Output**: Table, JSON, and SARIF formats
-   **Plugin Architecture**: Extensible with reconnaissance and security plugins
-   **TUI Interface**: Colorized terminal output with progress indicators

## 🛠️ Usage

### Basic Scan

```bash
# Scan a website
./run.sh scan https://example.com

# Scan with specific profile
./run.sh scan https://example.com --profile quick

# Scan with JSON output
./run.sh scan https://example.com --format json

# Enable AI analysis (if configured)
./run.sh scan https://example.com --ai
```

### Available Commands

```bash
# List available plugins
./run.sh plugins

# Show version information
./run.sh version

# Show help
./run.sh --help
```

## 🎯 Scan Profiles

-   **Quick**: Basic reconnaissance and obvious misconfigurations (fast)
-   **Standard**: Comprehensive scanning with common vulnerability checks
-   **Full**: All installed plugins with deep analysis

## 📊 Output Formats

-   **Table**: Human-readable terminal output (default)
-   **JSON**: Machine-readable JSON format
-   **SARIF**: Static Analysis Results Interchange Format

## 🔌 Plugins

The scanner includes several plugin types:

### Reconnaissance Plugins

-   HTTP Fingerprint
-   Technology Detection
-   TLS Analysis
-   Robots/Sitemap Analysis
-   Endpoint Discovery
-   Cookie Analysis
-   Header Analysis
-   Auth Discovery

### Security Analysis Plugins

-   XSS Detection
-   SQL Injection
-   CSRF Protection
-   And many more...

## 🧠 Intelligent Analysis Features

-   **Correlation Engine**: Identifies relationships between findings
-   **CVE Intelligence**: Matches findings with known vulnerabilities
-   **Dependency Analysis**: Checks for vulnerable dependencies
-   **Knowledge Base**: Provides remediation guidance and best practices
-   **Root Cause Analysis**: Identifies underlying systemic issues
-   **TUI Enhancements**: Colorized output and visual indicators

## 📦 Installation

### From Source

1.  Clone the repository
2.  Run `./build.sh`
3.  Use `./run.sh` to execute scans

### System Requirements

-   Rust 1.78+
-   Linux, macOS, or Windows (WSL)

## 🤝 Contributing

Contributions are welcome! Please see the main open-re project for contribution guidelines.

## 📄 License

MIT License - see LICENSE file for details.
