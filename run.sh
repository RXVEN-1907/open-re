#!/bin/bash

# Run script for the sentinel security scanner

set -e

# Check if binary exists
if [ ! -f "target/release/sentinel" ]; then
    echo "❌ Binary not found. Please build first with ./build.sh"
    exit 1
fi

# Run the scanner
echo "🚀 Running sentinel security scanner..."
./target/release/sentinel "$@"