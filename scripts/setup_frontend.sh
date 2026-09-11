#!/usr/bin/env bash
# setup_frontend.sh - Install frontend dependencies and start Vite dev server
set -e

# Change to frontend directory
cd frontend-dev/phantomnet-dashboard

# Install npm dependencies
npm install

# Start dev server
npm run dev
