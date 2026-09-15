#!/usr/bin/env bash
# setup_backend.sh - Install backend dependencies and run the FastAPI server
set -e

PYTHON=python3
if (! (Get-Command  -ErrorAction SilentlyContinue)) { Write-Error 'Python3 not found.'; exit 1 }

if (-Not (Test-Path '.venv')) { &  -m venv .venv }
& '.venv\Scripts\activate'

pip install --upgrade pip
pip install -r requirements.txt

if (Test-Path 'alembic.ini') { alembic upgrade head } 

uvicorn main:app --reload
