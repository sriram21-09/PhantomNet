import os
import re
import pytest
import yaml

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_docker_compose_postgres_pitr_configuration():
    """
    GOV-02: Verify that PostgreSQL in docker-compose.yml is strictly configured
    for continuous WAL archiving and RPO < 5 minute recovery.
    """
    compose_path = os.path.join(ROOT_DIR, "docker-compose.yml")
    assert os.path.exists(compose_path), "docker-compose.yml not found"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})
    assert "postgres" in services, "postgres service missing from docker-compose.yml"
    pg = services["postgres"]

    # Verify persistent volumes for WAL archiving and backups
    volumes = pg.get("volumes", [])
    vol_strings = [v if isinstance(v, str) else v.get("source", "") for v in volumes]

    archive_vol_present = any("postgres_archive" in v and "/var/lib/postgresql/archive" in v for v in vol_strings)
    backup_vol_present = any("postgres_backups" in v and "/var/lib/postgresql/backups" in v for v in vol_strings)

    assert archive_vol_present, "postgres_archive volume mapping to /var/lib/postgresql/archive is required"
    assert backup_vol_present, "postgres_backups volume mapping to /var/lib/postgresql/backups is required"

    # Verify top-level volumes declaration
    top_volumes = compose.get("volumes", {})
    assert "postgres_archive" in top_volumes, "postgres_archive volume missing in top-level volumes"
    assert "postgres_backups" in top_volumes, "postgres_backups volume missing in top-level volumes"

    # Verify PostgreSQL engine parameters in command string
    command = pg.get("command", "")
    assert "wal_level=replica" in command, "wal_level=replica required for PITR"
    assert "archive_mode=on" in command, "archive_mode=on required for continuous archiving"
    assert "archive_command" in command, "archive_command required for WAL segment preservation"

    # Verify RPO <= 5m constraint (archive_timeout <= 300 seconds)
    timeout_match = re.search(r"archive_timeout=(\d+)", command)
    assert timeout_match is not None, "archive_timeout must be configured"
    timeout_val = int(timeout_match.group(1))
    assert timeout_val <= 300, f"archive_timeout={timeout_val}s exceeds 300s (5-minute RPO SLO)"


def test_pitr_restore_script_integrity_and_semantics():
    """
    GOV-02: Verify that dr_pitr_restore.sh implements the required disaster recovery
    steps, validation logic, and PostgreSQL 12+ recovery semantics.
    """
    script_path = os.path.join(ROOT_DIR, "scripts", "dr_pitr_restore.sh")
    assert os.path.exists(script_path), "dr_pitr_restore.sh not found in scripts/"

    with open(script_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify safety and execution flags
    assert "set -euo pipefail" in content
    assert "--dry-run" in content

    # Verify PostgreSQL recovery configurations
    assert "recovery.signal" in content, "recovery.signal required for PostgreSQL 12+ recovery mode"
    assert "restore_command" in content, "restore_command must be set in postgresql.auto.conf"
    assert "recovery_target_time" in content, "recovery_target_time parameter required"
    assert "recovery_target_action" in content, "recovery_target_action must be configured (e.g. promote)"

    # Verify pre-restore safety snapshot
    assert "pre_restore_" in content, "Must preserve safety snapshot before overwriting data directory"

    # Verify readiness check
    assert "pg_isready" in content, "Must verify database readiness post-restore"
