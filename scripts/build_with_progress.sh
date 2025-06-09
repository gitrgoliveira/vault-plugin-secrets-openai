#!/bin/bash
# build_with_progress.sh - A script to show progress during Go builds
# It uses go list to count packages and then shows progress during build

set -e

# Directory containing the binary
BUILD_DIR="./bin"
# Plugin name
PLUGIN_NAME="vault-plugin-secrets-openai"
# Path to main package
MAIN_PKG="./cmd/${PLUGIN_NAME}"

# Count total packages that will be built
echo "Analyzing dependencies..."
# Use a more reliable method to count dependencies
TOTAL_PKGS=$(go list -e -f '{{if not .Standard}}1{{end}}' "$MAIN_PKG" $(go list -e -deps "$MAIN_PKG") | grep -c "1")

echo "Found $TOTAL_PKGS total dependency packages"

# Create build directory
mkdir -p $BUILD_DIR

# Check if the binary already exists
BINARY_PATH="$BUILD_DIR/$PLUGIN_NAME"
FORCE_REBUILD=false
CACHE_USED=false

# Check if we need to force a rebuild
if [ "$1" = "--force" ]; then
  echo "Force rebuild requested, cleaning build cache..."
  go clean -cache
  FORCE_REBUILD=true
elif [ -f "$BINARY_PATH" ]; then
  # Check if source files are newer than the binary
  NEWEST_GO_FILE=$(find . -name "*.go" -type f -newer "$BINARY_PATH" 2>/dev/null | head -1)
  if [ -z "$NEWEST_GO_FILE" ]; then
    echo "No Go files have changed since last build. Using cached binary."
    CACHE_USED=true
  else
    echo "Some Go files have changed. Rebuilding..."
  fi
fi

if [ "$CACHE_USED" = true ]; then
  # Just show a complete progress bar for cached builds
  PROGRESS=$(printf '%*s' 50 '' | tr ' ' '#')
  printf "[%s] 100%% (Cached build, no packages compiled)\n" "$PROGRESS"
  echo -e "Binary is up to date at: $BINARY_PATH"
  echo -e "Use '--force' flag to force a rebuild with full progress display."
else
  # Build with verbose flag and count packages as they're compiled
  COUNTER=0
  # Use a temporary file to avoid losing the counter due to subshell in the pipe
  TEMP_FILE=$(mktemp)
  trap "rm -f $TEMP_FILE" EXIT

  # Build with verbose output
  echo "Building..."
  go build -v -o $BUILD_DIR/$PLUGIN_NAME $MAIN_PKG 2>&1 | tee $TEMP_FILE | while IFS= read -r line; do
    if [[ $line =~ ^[a-z0-9_.-]+/[a-z0-9_.-]+(/[a-z0-9_.-]+)* ]]; then
      COUNTER=$((COUNTER + 1))
      PCT=$((COUNTER * 100 / TOTAL_PKGS))
      if [ $PCT -gt 100 ]; then
        PCT=100
      fi
      # Create a simple progress bar
      PROGRESS=$(printf '%*s' $((PCT / 2)) '' | tr ' ' '#')
      printf "\r[%-50s] %3d%% (%d/%d) %s" "$PROGRESS" "$PCT" "$COUNTER" "$TOTAL_PKGS" "$line"
    else
      echo "$line"
    fi
  done

  # Count how many packages were actually compiled
  COMPILED_PKGS=$(grep -c '^[a-z0-9_.-]\+/[a-z0-9_.-]\+\(/[a-z0-9_.-]\+\)*$' $TEMP_FILE || echo 0)

  if [ "$COMPILED_PKGS" -eq 0 ]; then
    echo -e "\nBuild complete! No packages needed compiling (using cached objects)."
  else
    echo -e "\nBuild complete! Compiled $COMPILED_PKGS packages."
  fi
  echo "Binary at: $BINARY_PATH"
fi
