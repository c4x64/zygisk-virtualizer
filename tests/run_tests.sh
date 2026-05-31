#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Zygisk Virtualizer Test Suite"
echo "=============================="
echo

# Build tests
echo "Building tests..."
make -C "$SCRIPT_DIR" clean all 2>&1
echo

# Run unit tests
passed=0
failed=0
failed_tests=""

echo "--- Unit Tests ---"
for test in "$SCRIPT_DIR"/unit/test_*; do
    if [ -f "$test" ] && [ -x "$test" ]; then
        name=$(basename "$test")
        echo "Running $name..."
        if "$test"; then
            echo "$name: PASS"
            passed=$((passed + 1))
        else
            echo "$name: FAIL"
            failed=$((failed + 1))
            failed_tests="$failed_tests $name"
        fi
        echo
    fi
done

echo "=== Summary ==="
echo "Passed: $passed"
echo "Failed: $failed"
if [ -n "$failed_tests" ]; then
    echo "Failed tests:$failed_tests"
fi
echo

if [ "$failed" -gt 0 ]; then
    echo "Some tests FAILED."
    exit 1
fi
echo "All tests passed."
exit 0
