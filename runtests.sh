#!/bin/bash

# WebSocket Client Test Runner
# Usage: ./run_tests.sh

set -e  # Exit on any error

echo "Building and running WebSocket Client tests..."
echo "=============================================="

# Build the tests
echo "Building tests..."
gn gen out/test --args="is_debug=true"
ninja -C out/test websocket_tests

# Run the tests
echo ""
echo "Running tests..."
echo "----------------"
./out/test/websocket_tests

echo ""
echo "Test run complete!"