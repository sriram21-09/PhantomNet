"""
OPS-06: End-to-End Migration -> Readiness -> Rollback -> Readiness Test Suite.

Acceptance Criteria:
1. Migration -> readiness -> rollback -> readiness succeeds without residual schema problems.
2. Evidence needed: Executable forward/rollback test.
3. Verifies schema integrity at baseline, after forward migration, and after clean rollback.
4. Verifies zero residual locks, correct alembic_version tracking, and passing /health/ready probes.
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest
from sqlalchemy import create_engine, inspect, text
from alembic.config import Config
from alembic import command
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.database import get_db
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ALEMBIC_INI_PATH = PROJECT_ROOT / "alembic.ini"
VERSIONS_DIR = PROJECT_ROOT / "backend" / "alembic" / "versions"
CANARY_REV_ID = "c987654321ab"
CANARY_FILE = VERSIONS_DIR / f"{CANARY_REV_ID}_test_ops06_canary.py"


CANARY_MIGRATION_CONTENT = f'''"""test_ops06_canary

Revision ID: {CANARY_REV_ID}
Revises: b38a3ae24623
Create Date: 2026-09-19 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '{CANARY_REV_ID}'
down_revision: Union[str, Sequence[str], None] = 'b38a3ae24623'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ops06_schema_canary',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('canary_name', sa.String(length=100), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False, server_default='1'),
    )
    op.create_index('ix_ops06_canary_name', 'ops06_schema_canary', ['canary_name'])


def downgrade() -> None:
    op.drop_index('ix_ops06_canary_name', table_name='ops06_schema_canary')
    op.drop_table('ops06_schema_canary')
'''


@pytest.fixture
def temp_migration_db():
    """Creates a dedicated temporary SQLite DB file for migration testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    # Normalize path for SQLite URL
    normalized_path = db_path.replace("\\", "/")
    db_url = f"sqlite:///{normalized_path}"

    yield db_url, db_path

    # Cleanup DB file after test
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


def get_alembic_config(db_url: str) -> Config:
    """Configures Alembic pointing to alembic.ini with the target DB URL."""
    cfg = Config(str(ALEMBIC_INI_PATH))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "backend" / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_migration_forward_rollback_e2e_lifecycle(temp_migration_db):
    """
    Executes the full OPS-06 verification cycle:
    1. Upgrade to baseline (b38a3ae24623).
    2. Verify readiness probe passes.
    3. Introduce new migration revision (c987654321ab).
    4. Upgrade to head.
    5. Verify canary table exists, accepts writes, and readiness passes.
    6. Rollback to baseline (b38a3ae24623).
    7. Verify canary table is removed, baseline tables intact, no residual locks.
    8. Verify readiness probe passes post-rollback.
    """
    db_url, db_path = temp_migration_db
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    cfg = get_alembic_config(db_url)

    # FastAPI TestClient with DB dependency override
    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        # -------------------------------------------------------------
        # STEP 1: Baseline Migration (b38a3ae24623)
        # -------------------------------------------------------------
        command.upgrade(cfg, "b38a3ae24623")

        inspector = inspect(engine)
        tables = inspector.get_table_names()
        assert "users" in tables, "Baseline migration must create 'users' table"
        assert "audit_logs" in tables, "Baseline migration must create 'audit_logs' table"
        assert "packet_logs" in tables, "Baseline migration must create 'packet_logs' table"
        assert "alembic_version" in tables, "Baseline migration must create 'alembic_version' table"

        with engine.connect() as conn:
            current_ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert current_ver == "b38a3ae24623", f"Expected version b38a3ae24623, got {current_ver}"

        # -------------------------------------------------------------
        # STEP 2: Baseline Readiness Probe
        # -------------------------------------------------------------
        ready_res1 = client.get("/health/ready")
        assert ready_res1.status_code == 200, f"Readiness probe failed at baseline: {ready_res1.json()}"
        assert ready_res1.json()["checks"]["postgres"] == "healthy"

        # -------------------------------------------------------------
        # STEP 3: Create Dynamic Forward Migration Revision
        # -------------------------------------------------------------
        with open(CANARY_FILE, "w", encoding="utf-8") as f:
            f.write(CANARY_MIGRATION_CONTENT)

        assert CANARY_FILE.exists(), f"Canary migration file {CANARY_FILE} must exist"

        # -------------------------------------------------------------
        # STEP 4: Forward Migration Execution (Upgrade to Head)
        # -------------------------------------------------------------
        command.upgrade(cfg, "head")

        inspector = inspect(engine)
        tables_after_upgrade = inspector.get_table_names()
        assert "ops06_schema_canary" in tables_after_upgrade, "Forward migration must create 'ops06_schema_canary'"

        with engine.connect() as conn:
            current_ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert current_ver == CANARY_REV_ID, f"Expected version {CANARY_REV_ID}, got {current_ver}"

            # Verify table is writable and functional
            conn.execute(
                text("INSERT INTO ops06_schema_canary (id, canary_name, active) VALUES (1, 'canary-probe', 1)")
            )
            conn.commit()
            row = conn.execute(text("SELECT canary_name FROM ops06_schema_canary WHERE id = 1")).scalar()
            assert row == "canary-probe"

        # -------------------------------------------------------------
        # STEP 5: Post-Upgrade Readiness Probe
        # -------------------------------------------------------------
        ready_res2 = client.get("/health/ready")
        assert ready_res2.status_code == 200, f"Readiness probe failed after forward migration: {ready_res2.json()}"
        assert ready_res2.json()["checks"]["postgres"] == "healthy"

        # -------------------------------------------------------------
        # STEP 6: Rollback Migration Execution (Downgrade to Baseline)
        # -------------------------------------------------------------
        command.downgrade(cfg, "b38a3ae24623")

        # -------------------------------------------------------------
        # STEP 7: Rollback Verification
        # -------------------------------------------------------------
        inspector = inspect(engine)
        tables_after_downgrade = inspector.get_table_names()
        assert "ops06_schema_canary" not in tables_after_downgrade, (
            "Rolled-back table 'ops06_schema_canary' must not exist in schema"
        )
        assert "users" in tables_after_downgrade, "Baseline table 'users' must remain intact"
        assert "audit_logs" in tables_after_downgrade, "Baseline table 'audit_logs' must remain intact"

        with engine.connect() as conn:
            current_ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert current_ver == "b38a3ae24623", f"Alembic version must revert to b38a3ae24623, got {current_ver}"

            # Verify queries on core tables work cleanly without lock or corruption
            user_count = conn.execute(text("SELECT count(*) FROM users")).scalar()
            assert isinstance(user_count, int)

        # -------------------------------------------------------------
        # STEP 8: Post-Rollback Readiness Probe
        # -------------------------------------------------------------
        ready_res3 = client.get("/health/ready")
        assert ready_res3.status_code == 200, f"Readiness probe failed after rollback: {ready_res3.json()}"
        assert ready_res3.json()["checks"]["postgres"] == "healthy"

    finally:
        # Clean up dependency overrides
        app.dependency_overrides.clear()
        engine.dispose()

        # Clean up canary migration file
        if CANARY_FILE.exists():
            try:
                os.remove(CANARY_FILE)
            except OSError:
                pass
