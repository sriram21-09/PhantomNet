import os
import sys
import tempfile
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


@pytest.fixture
def temp_alembic_db():
    """Provides a fresh temporary SQLite database path for isolated migration testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


def get_alembic_config(db_path: str) -> Config:
    """Configures Alembic to use the temporary database."""
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_dir = os.path.abspath(os.path.join(backend_dir, ".."))
    
    ini_path = os.path.join(root_dir, "alembic.ini")
    if not os.path.exists(ini_path):
        ini_path = os.path.join(backend_dir, "alembic.ini")

    config = Config(ini_path)
    sqlite_url = f"sqlite:///{db_path.replace(os.sep, '/')}"
    config.set_main_option("sqlalchemy.url", sqlite_url)
    return config


def test_alembic_four_stage_safety_protocol(temp_alembic_db):
    """
    GOV-01: 4-Stage Migration Safety Protocol
    Stage 1: Clean upgrade on empty DB (alembic upgrade head).
    Stage 2: Schema verification (all tables & critical indexes created).
    Stage 3: Full rollback (alembic downgrade base) with 0 errors.
    Stage 4: Re-upgrade to head, schema drift verification, and functional write.
    """
    config = get_alembic_config(temp_alembic_db)
    sqlite_url = f"sqlite:///{temp_alembic_db.replace(os.sep, '/')}"
    engine = create_engine(sqlite_url)

    # ----------------------------------------------------
    # STAGE 1: Empty Database Upgrade to Head
    # ----------------------------------------------------
    command.upgrade(config, "head")

    # ----------------------------------------------------
    # STAGE 2: Table & Index Verification
    # ----------------------------------------------------
    with engine.connect() as conn:
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())

        expected_tables = {
            "packet_logs",
            "alerts",
            "traffic_stats",
            "attack_sessions",
            "events",
            "honeypot_nodes",
            "policies",
            "scheduled_reports",
            "investigation_cases",
            "case_evidence",
            "iocs",
            "search_history",
            "pcap_captures",
            "users",
            "system_config",
            "refresh_tokens",
            "taxii_clients",
            "audit_logs",
            "sentinel_playbooks",
            "alembic_version",
        }
        for expected in expected_tables:
            assert expected in tables, f"Expected table '{expected}' was not created by Alembic migration!"

        # Verify critical Phase 2 columns in packet_logs
        pl_cols = {c["name"] for c in inspector.get_columns("packet_logs")}
        assert "event_id" in pl_cols
        assert "canonical_fingerprint" in pl_cols
        assert "honeypot_id" in pl_cols
        assert "raw_payload" in pl_cols

        # Verify audit_logs columns
        al_cols = {c["name"] for c in inspector.get_columns("audit_logs")}
        assert "actor" in al_cols
        assert "record_hash" in al_cols
        assert "previous_hash" in al_cols

    # ----------------------------------------------------
    # STAGE 3: Rollback to Base (Clean Drop)
    # ----------------------------------------------------
    command.downgrade(config, "base")

    with engine.connect() as conn:
        inspector = inspect(conn)
        remaining_tables = set(inspector.get_table_names())
        # Only alembic_version (or nothing) should remain after full downgrade
        remaining_user_tables = remaining_tables - {"alembic_version"}
        assert len(remaining_user_tables) == 0, f"Tables remained after downgrade to base: {remaining_user_tables}"

    # ----------------------------------------------------
    # STAGE 4: Re-Upgrade, Functional Insert & Check
    # ----------------------------------------------------
    command.upgrade(config, "head")

    # Verify functional insert on re-upgraded database
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, hashed_password, role, status) "
                "VALUES ('admin_test', 'admin@phantomnet.local', 'secret_hash', 'Admin', 'active')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO packet_logs (src_ip, dst_ip, src_port, dst_port, protocol, length, event_id) "
                "VALUES ('192.168.1.10', '192.168.1.1', 44321, 22, 'TCP', 64, '018f6c3a-9921-7000-8000-000000000001')"
            )
        )
        result = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
        assert result == 1

        pl_count = conn.execute(text("SELECT COUNT(*) FROM packet_logs")).scalar()
        assert pl_count == 1

    # Check for pending autogenerate differences (must be clean zero drift)
    command.check(config)


def test_existing_db_stamping_and_idempotent_upgrade(temp_alembic_db):
    """
    Verifies that an existing database baseline can be stamped and verified
    without schema corruption or failure.
    """
    config = get_alembic_config(temp_alembic_db)
    sqlite_url = f"sqlite:///{temp_alembic_db.replace(os.sep, '/')}"
    engine = create_engine(sqlite_url)

    # First upgrade to head
    command.upgrade(config, "head")

    # Stamp head idempotently
    command.stamp(config, "head")

    # Ensure upgrade head is idempotent
    command.upgrade(config, "head")

    with engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version is not None
        assert len(version) > 0
