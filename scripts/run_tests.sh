#!/bin/bash

# Run all unit tests
echo "=== Running unit tests ==="
go test -v ./...

# Check if we should run integration tests
if [ "$1" == "--integration" ]; then
    echo -e "\n=== Running integration tests ==="
    # Add integration test commands here when they are implemented
    echo "Integration tests not yet implemented"
fi

# Check if any of the tests failed
if [ $? -ne 0 ]; then
    echo -e "\n❌ Tests failed"
    exit 1
else
    echo -e "\n✅ All tests passed"
    exit 0
fi
