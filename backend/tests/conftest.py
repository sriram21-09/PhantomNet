import pytest
from datetime import datetime, timedelta

@pytest.fixture
def mock_ssh_event():
    return {
        "timestamp": datetime.now(),
        "attacker_ip": "192.168.1.50",
        "service_type": "SSH",
        "username": "admin",
        "password": "password123"
    }

@pytest.fixture
def mock_anomalous_event():
    return {
        "timestamp": datetime.now(),
        "attacker_ip": "45.33.22.11",
        "service_type": "SSH",
        "username": "x8s9d8fs9d8", # Random username
        "password": "J@#($*!@#)(das", # High entropy password
    }

@pytest.fixture
def mock_http_event():
    return {
        "timestamp": datetime.now(),
        "attacker_ip": "10.0.0.5",
        "service_type": "HTTP",
        "username": "guest",
        "password": "guest"
    }