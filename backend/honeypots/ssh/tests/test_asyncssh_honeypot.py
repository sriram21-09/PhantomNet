import asyncio
import asyncssh
import pytest
import os
import json

HOST = "phantomnet_postgres"
PORT = 2222

VALID_USER = "PhantomNet"
VALID_PASS = "1234"

INVALID_USER = "attacker"
INVALID_PASS = "wrongpass"

LOG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../logs/ssh_async.jsonl")
)

@pytest.mark.asyncio
async def test_invalid_login():
    """Invalid credentials should fail"""
    with pytest.raises((asyncssh.PermissionDenied, asyncssh.misc.ConnectionLost)):
        await asyncssh.connect(
            HOST,
            PORT,
            username=INVALID_USER,
            password=INVALID_PASS,
            known_hosts=None
        )

@pytest.mark.asyncio
async def test_valid_login():
    """Valid credentials should succeed"""
    conn = await asyncssh.connect(
        HOST,
        PORT,
        username=VALID_USER,
        password=VALID_PASS,
        known_hosts=None
    )
    conn.close()

def test_asyncssh_login_logs_exist():
    """Check login_attempt logs contain username, password, and level"""
    assert os.path.exists(LOG_FILE)

    with open(LOG_FILE, "r") as f:
        logs = [json.loads(line) for line in f]

    login_logs = [
        log for log in logs
        if log.get("event") == "login_attempt"
    ]

    assert len(login_logs) > 0

    sample = login_logs[-1]

    # Validate structure
    assert "data" in sample
    assert "username" in sample["data"]
    assert "password" in sample["data"]

    # Validate log level
    assert "level" in sample
    assert sample["level"] in ("INFO", "WARN", "ERROR")
