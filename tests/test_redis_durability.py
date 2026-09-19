"""
Test Suite: Redis Durability & Network Topology Configuration Audit (DUR-03)
Validates:
1. AOF persistence is explicitly enabled with 'appendonly yes'.
2. Fsync frequency is set to 'appendfsync everysec' (RPO <= 1 sec).
3. Memory eviction policy is strictly 'noeviction' to prevent silent data loss under pressure.
4. Persistent volume 'redis_data' is mounted to '/data'.
5. Network isolation: Redis is connected ONLY to internal broker networks and NOT exposed to honeypot_net.
"""
import os
import yaml
import pytest


def load_docker_compose_config():
    compose_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
    )
    assert os.path.exists(compose_path), f"docker-compose.yml not found at {compose_path}"
    with open(compose_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_redis_service_exists_and_uses_official_image():
    config = load_docker_compose_config()
    services = config.get("services", {})
    assert "redis" in services, "Redis service missing from docker-compose.yml"
    
    redis_service = services["redis"]
    image = redis_service.get("image", "")
    assert "redis:" in image, f"Unexpected image for redis service: {image}"


def test_redis_aof_durability_and_fsync():
    config = load_docker_compose_config()
    redis_service = config["services"]["redis"]
    command = redis_service.get("command", "")

    # 1. AOF must be enabled
    assert "--appendonly yes" in command, "Redis must have '--appendonly yes' for AOF persistence"

    # 2. Fsync policy must be everysec
    assert "--appendfsync everysec" in command, "Redis must enforce '--appendfsync everysec'"


def test_redis_noeviction_policy():
    config = load_docker_compose_config()
    redis_service = config["services"]["redis"]
    command = redis_service.get("command", "")

    # Eviction policy must be noeviction so write operations fail fast rather than silently dropping data
    assert "--maxmemory-policy noeviction" in command, (
        "Redis must use '--maxmemory-policy noeviction' to prevent data loss on saturation"
    )


def test_redis_persistent_volume_mount():
    config = load_docker_compose_config()
    redis_service = config["services"]["redis"]
    volumes = redis_service.get("volumes", [])
    
    # Check volume mounting /data
    has_data_mount = any(
        isinstance(v, str) and (v.startswith("redis_data:") or v.endswith(":/data"))
        for v in volumes
    )
    assert has_data_mount, "Redis service must mount persistent volume 'redis_data' to '/data'"

    declared_volumes = config.get("volumes", {})
    assert "redis_data" in declared_volumes, "Volume 'redis_data' must be declared in root volumes block"


def test_redis_network_isolation():
    config = load_docker_compose_config()
    redis_service = config["services"]["redis"]
    networks = redis_service.get("networks", [])

    # Redis must NOT be directly reachable from untrusted honeypots!
    assert "honeypot_net" not in networks, "SECURITY RISK: Redis must NEVER be connected to honeypot_net"

    # Redis must be on internal broker and app networks
    assert "internal_broker_net" in networks, "Redis must be connected to internal_broker_net"
    assert "app_net" in networks, "Redis must be connected to app_net"


def test_honeypots_decoupled_from_postgres():
    config = load_docker_compose_config()
    services = config.get("services", {})
    honeypot_names = ["ssh_honeypot", "http_honeypot", "ftp_honeypot", "smtp-honeypot"]

    for hp in honeypot_names:
        if hp in services:
            hp_conf = services[hp]
            networks = hp_conf.get("networks", [])
            assert "app_net" not in networks, f"Honeypot {hp} must not be directly on app_net"
            env = hp_conf.get("environment", {})
            if isinstance(env, dict):
                assert "DATABASE_URL" not in env, f"Honeypot {hp} must NOT contain DATABASE_URL credentials"
                assert "INGESTION_GATEWAY_URL" in env, f"Honeypot {hp} must point to INGESTION_GATEWAY_URL"
