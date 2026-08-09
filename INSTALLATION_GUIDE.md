# Installation Guide

## System Requirements

- Rust 1.78 or higher
- Cargo package manager
- Git (for cloning the repository)

## Installation Options

### Option 1: Build from Source (Recommended)

1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/RXVEN-1907/open-re.git
   cd open-re
   ```

3. **Build the scanner**:
   ```bash
   ./build.sh
   ```

4. **Verify installation**:
   ```bash
   ./run.sh version
   ```

### Option 2: Direct Cargo Installation

If you want to install directly with Cargo:

```bash
cargo install --path crates/openre-scanner
```

Then run with:
```bash
sentinel --help
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install build-essential git curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
./build.sh
```

### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install rust git

# Clone and build
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
./build.sh
```

### Windows (WSL)

1. Install Windows Subsystem for Linux (WSL2)
2. Install Ubuntu from Microsoft Store
3. Follow the Linux instructions above

## Verifying Installation

After installation, verify that everything works:

```bash
# Check version
./run.sh version

# Show help
./run.sh --help

# Run a quick scan on a test target
./run.sh scan https://httpbin.org --profile quick
```

## Troubleshooting

### Build Errors

If you encounter build errors:

1. **Update Rust**:
   ```bash
   rustup update
   ```

2. **Clear Cargo cache**:
   ```bash
   cargo clean
   ```

3. **Check dependencies**:
   Make sure you have build essentials installed (build-essential on Ubuntu, Xcode Command Line Tools on macOS)

### Runtime Issues

If the scanner fails to run:

1. **Check permissions**:
   ```bash
   chmod +x ./run.sh
   ```

2. **Verify binary exists**:
   ```bash
   ls -la target/release/sentinel
   ```

3. **Check network connectivity**:
   Some scans require internet access for CVE lookups and external services

## Updating

To update to the latest version:

```bash
# Pull latest changes
git pull origin main

# Rebuild
./build.sh
```

## Uninstalling

To uninstall:

1. Remove the cloned repository:
   ```bash
   cd ../
   rm -rf open-re/
   ```

2. If installed via Cargo directly:
   ```bash
   cargo uninstall sentinel
   ```