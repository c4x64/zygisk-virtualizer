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
echo "--- Unit Tests ---"
for test in "$SCRIPT_DIR"/unit/test_*; do
    if [ -f "$test" ] && [ -x "$test" ]; then
        echo "Running $(basename "$test")..."
        "$test" || true
        echo
    fi
done

# Check if there are compiled test binaries in the test root too
for test in "$SCRIPT_DIR"/test_trie "$SCRIPT_DIR"/test_cache "$SCRIPT_DIR"/test_rules; do
    if [ -f "$test" ] && [ -x "$test" ]; then
        echo "Running $(basename "$test")..."
        "$test" || true
        echo
    fi
done

echo "All tests completed."
