#!/bin/bash
set -e

BINARY="./target/release/openre-scan"
TARGET_QUICK="https://example.com"
TARGET_STANDARD="https://httpbin.org"
TARGET_FULL="https://httpbin.org"

echo "=== openre-scan Benchmark ==="
echo "Binary: $BINARY"
echo "Binary size: $(ls -lh $BINARY | awk '{print $5}')"
echo "Binary sha256: $(sha256sum $BINARY | awk '{print $1}')"
echo ""

# Startup time
echo "=== Startup Time (10 runs) ==="
TOTAL=0
for i in {1..10}; do
    START=$(date +%s.%N)
    $BINARY version > /dev/null 2>&1
    END=$(date +%s.%N)
    DIFF=$(echo "$END - $START" | bc -l)
    TOTAL=$(echo "$TOTAL + $DIFF" | bc -l)
done
AVG=$(echo "scale=6; $TOTAL / 10" | bc -l)
echo "Average startup time: ${AVG}s"
echo ""

# Scan duration benchmarks
echo "=== Scan Duration Benchmarks ==="
echo "Quick profile (6 checks) against $TARGET_QUICK:"
/usr/bin/time -f "  Real: %e s, User: %U s, Sys: %S s, Max RSS: %M KB" $BINARY scan $TARGET_QUICK --profile quick --no-progress > /dev/null 2>&1

echo "Standard profile (15 checks) against $TARGET_STANDARD:"
/usr/bin/time -f "  Real: %e s, User: %U s, Sys: %S s, Max RSS: %M KB" $BINARY scan $TARGET_STANDARD --profile standard --no-progress > /dev/null 2>&1

echo "Full profile (18 checks) against $TARGET_FULL:"
timeout 180 /usr/bin/time -f "  Real: %e s, User: %U s, Sys: %S s, Max RSS: %M KB" $BINARY scan $TARGET_FULL --profile full --no-progress > /dev/null 2>&1 || echo "  Timed out or failed"
echo ""

# Output format overhead
echo "=== Output Format Overhead (quick scan) ==="
echo "Table format:"
/usr/bin/time -f "  Real: %e s" $BINARY scan $TARGET_QUICK --profile quick --format table --no-progress > /dev/null 2>&1

echo "JSON format:"
/usr/bin/time -f "  Real: %e s" $BINARY scan $TARGET_QUICK --profile quick --format json --no-progress > /dev/null 2>&1

echo "SARIF format:"
/usr/bin/time -f "  Real: %e s" $BINARY scan $TARGET_QUICK --profile quick --format sarif --no-progress > /dev/null 2>&1
echo ""

echo "=== Benchmark Complete ==="
