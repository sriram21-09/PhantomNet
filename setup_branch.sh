#!/usr/bin/env bash
# setup_branch.sh
# This script creates a fresh clone of the repository in a temporary directory
# and checks out a new branch for verification.

set -e

# Define temporary clone location
TMP_DIR="${TMPDIR:-/tmp}/phantomnet_fresh"

# Remove any existing clone
if [ -d "$TMP_DIR" ]; then
  echo "Removing existing temporary clone at $TMP_DIR"
  rm -rf "$TMP_DIR"
fi

# Clone the repository (replace with actual repo URL if needed)
REPO_URL="$(git config --get remote.origin.url)"
if [ -z "$REPO_URL" ]; then
  echo "Unable to determine repository URL from git config. Using placeholder."
  REPO_URL="https://github.com/sriram21-09/PhantomNet.git"
fi

echo "Cloning repository..."
git clone "$REPO_URL" "$TMP_DIR"

cd "$TMP_DIR"

# Create and switch to verification branch
BRANCH_NAME="first-time-setup-verification"

git checkout -b "$BRANCH_NAME"

echo "Repository cloned to $TMP_DIR and switched to branch $BRANCH_NAME"
