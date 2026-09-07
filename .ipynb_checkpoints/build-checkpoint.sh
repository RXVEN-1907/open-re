#!/bin/bash

# Build script for the sentinel security scanner

set -e

echo "🔍 Building sentinel security scanner..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
cargo clean -p sentinel

# Build in release mode
echo "🔨 Building in release mode..."
cargo build --release -p sentinel

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo "📦 Binary location: target/release/sentinel"
    echo "🚀 To run: ./target/release/sentinel --help"
else
    echo "❌ Build failed!"
    exit 1
fi