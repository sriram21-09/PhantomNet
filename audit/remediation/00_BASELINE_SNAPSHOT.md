# PHANTOMNET V3 — REMEDIATION BASELINE SNAPSHOT

**Timestamp**: 2026-09-19T14:00:00Z
**Branch**: fix/full-codebase-audit-remediation
**Git Commit**: 8c199f28
**Python Version**: 3.11.9
**Node Version**: v24.11.1
**Docker Version**: 29.6.2 (build dfc4efb)
**Docker Compose Version**: v5.3.1
**Alembic Migration State**: b38a3ae24623 (head)

## Docker Containers & Images Active
- phantomnet_api (phantomnet-api:latest) -> port 8000
- phantomnet_postgres (postgres:15-alpine) -> port 5432
- phantomnet_redis (redis:7-alpine) -> port 6379
- phantomnet_ollama (ollama/ollama:latest) -> port 11434

## Initial 42-Dimension Revalidation Baseline
- **VERIFIED (🟢)**: 26 / 42 (61.9%)
- **PARTIALLY VERIFIED (🟡)**: 2 / 42 (4.8%)
- **NOT VERIFIED (🔴)**: 14 / 42 (33.3%)
- **Verdict**: PRODUCTION DEPLOYMENT BLOCKED

## SHA-256 Manifest
See `audit/remediation/baseline_manifest.sha256` for exact hashes of all baseline source and audit artifacts prior to remediation.
