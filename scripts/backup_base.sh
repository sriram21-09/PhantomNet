#!/usr/bin/env bash
# ==============================================================================
# PhantomNet - PostgreSQL Hot Base Backup Script (GOV-02)
# ==============================================================================
# Generates a non-blocking hot physical base backup using pg_basebackup.
#
# Usage:
#   bash scripts/backup_base.sh [CONTAINER_NAME] [BACKUP_DIR]
# ==============================================================================

set -euo pipefail

CONTAINER="${1:-phantomnet_postgres}"
BACKUP_DIR="${2:-/var/lib/postgresql/backups}"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/base_${TIMESTAMP}.tar.gz"

echo "======================================================================"
echo " Starting PostgreSQL Base Backup for ${CONTAINER}"
echo " Timestamp: ${TIMESTAMP} UTC"
echo " Destination: ${BACKUP_FILE}"
echo "======================================================================"

# Execute pg_basebackup inside the container
docker exec "${CONTAINER}" bash -c "
    mkdir -p '${BACKUP_DIR}' && \
    pg_basebackup -U \${POSTGRES_USER:-postgres} \
                  -D - \
                  -Ft \
                  -z \
                  -P \
                  -X stream > '${BACKUP_FILE}'
"

echo "✅ Hot Base Backup successfully created: ${BACKUP_FILE}"
