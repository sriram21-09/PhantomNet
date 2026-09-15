#!/usr/bin/env bash
# frontend_install.sh
# Installs frontend dependencies for the PhantomNet dashboard and starts the dev server.

set -e

# Navigate to the frontend dashboard directory (script should be run from repo root)
cd "$(dirname "$0")/frontend-dev/phantomnet-dashboard"

# Ensure a clean install using npm ci (fails if package-lock missing, falls back to npm install)
if [ -f "package-lock.json" ]; then
  echo "Running npm ci for a clean install..."
  npm ci
else
  echo "package-lock.json not found, performing npm install..."
  npm install
fi

# Build the project to verify no build errors
echo "Building the frontend..."
npm run build

# Start the Vite dev server in background
echo "Starting the frontend dev server..."
if [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "win32"* ]]; then
  start /B npm run dev > frontend_log.txt 2>&1
else
  nohup npm run dev > frontend_log.txt 2>&1 &
fi

echo "Frontend installation complete. Server logs at frontend_log.txt"
