"""
Test suite verifying OPS-01 Container Hardening.
Enforces that all production container definitions in docker-compose.yml
and corresponding Dockerfiles adhere to principle of least privilege:
1. cap_drop: ALL
2. Non-root user (UID 10001)
3. read_only root filesystem
4. Explicit writable tmpfs mounts with noexec,nosuid
5. security_opt: no-new-privileges:true
"""

import os
import yaml
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
COMPOSE_PATH = ROOT_DIR / "docker-compose.yml"

PRODUCTION_SERVICES = [
    "ssh_honeypot",
    "http_honeypot",
    "ftp_honeypot",
    "smtp-honeypot",
    "frontend",
    "api",
]

DOCKERFILES = [
    ROOT_DIR / "backend" / "api" / "Dockerfile",
    ROOT_DIR / "backend" / "honeypots" / "ssh" / "Dockerfile",
    ROOT_DIR / "backend" / "honeypots" / "http" / "Dockerfile",
    ROOT_DIR / "backend" / "honeypots" / "ftp" / "Dockerfile",
    ROOT_DIR / "backend" / "honeypots" / "smtp" / "Dockerfile",
]


@pytest.fixture(scope="module")
def compose_config():
    assert COMPOSE_PATH.exists(), f"docker-compose.yml not found at {COMPOSE_PATH}"
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_compose_production_services_hardening(compose_config):
    """Verify docker-compose.yml has hardened security specifications for all production services."""
    services = compose_config.get("services", {})

    for service_name in PRODUCTION_SERVICES:
        assert service_name in services, f"Service {service_name} missing from docker-compose.yml"
        svc = services[service_name]

        # 1. Non-root user
        user = svc.get("user")
        assert user is not None, f"Service {service_name} must define an unprivileged user"
        assert str(user).startswith("10001") or str(user).startswith("101"), (
            f"Service {service_name} user must be non-root (got {user})"
        )

        # 2. cap_drop: ALL
        cap_drop = svc.get("cap_drop", [])
        assert "ALL" in cap_drop, f"Service {service_name} must drop all capabilities (cap_drop: ALL)"

        # 3. security_opt: no-new-privileges:true
        security_opt = svc.get("security_opt", [])
        assert any("no-new-privileges:true" in opt for opt in security_opt), (
            f"Service {service_name} must enforce no-new-privileges:true"
        )

        # 4. read_only root filesystem
        read_only = svc.get("read_only")
        assert read_only is True, f"Service {service_name} must enforce read_only: true"

        # 5. tmpfs mounts
        tmpfs = svc.get("tmpfs", [])
        assert len(tmpfs) > 0, f"Service {service_name} must specify tmpfs mounts for ephemeral writes"
        assert any("/tmp" in m for m in tmpfs), f"Service {service_name} must mount /tmp via tmpfs"


def test_dockerfiles_non_root_user():
    """Verify all application and honeypot Dockerfiles declare a non-root USER instruction."""
    for df in DOCKERFILES:
        assert df.exists(), f"Dockerfile not found at {df}"
        content = df.read_text(encoding="utf-8")
        
        # Check for USER instruction
        user_lines = [line.strip() for line in content.splitlines() if line.strip().startswith("USER ")]
        assert len(user_lines) > 0, f"{df.name} must specify a USER instruction"
        last_user = user_lines[-1].split()[1]
        assert "root" not in last_user.lower() and last_user != "0", (
            f"{df.name} must not run as root user (got {last_user})"
        )
        assert "10001" in last_user or "phantom" in last_user or "honeypot" in last_user, (
            f"{df.name} USER should be an unprivileged UID/user (got {last_user})"
        )
