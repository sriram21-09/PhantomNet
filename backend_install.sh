#!/usr/bin/env bash
# backend_install.sh
# Installs backend Python dependencies, runs migrations, and starts the FastAPI server.

set -e

# Navigate to backend directory (script should be run from repo root)
cd "$(dirname "$0")/backend"

# Create virtual environment if not exists
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python -m venv .venv
fi

# Activate virtual environment
# Windows PowerShell activation handling
if [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "win32"* ]]; then
  source .venv/Scripts/activate
else
  source .venv/bin/activate
fi

# Upgrade pip and install requirements
pip install --upgrade pip
pip install -r requirements.txt

# Run database migrations (Alembic)
if command -v alembic >/dev/null 2>&1; then
  alembic upgrade head
else
  echo "Alembic not installed; installing..."
  pip install alembic
  alembic upgrade head
fi

# Start FastAPI server in background
# Use nohup on Unix, start-process on Windows
echo "Starting FastAPI server..."
if [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "win32"* ]]; then
  start /B uvicorn main:app --host 0.0.0.0 --port 8000 --reload > backend_log.txt 2>&1
else
  nohup uvicorn main:app --host 0.0.0.0 --port 8000 --reload > backend_log.txt 2>&1 &
fi

echo "Backend installation complete. Server logs at backend_log.txt"
