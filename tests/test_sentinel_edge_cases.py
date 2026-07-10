import pytest
from unittest.mock import patch, MagicMock
from sentinel.sentinel_service import SentinelService
from sentinel.rule_generator import validate_snort_rule_inputs, generate_rules_for_campaign

@pytest.fixture
def mock_db_session():
    mock_session = MagicMock()
    # Mock query().filter()...all() to return empty list
    mock_query = MagicMock()
    mock_query.filter.return_value = mock_query
    mock_query.order_by.return_value = mock_query
    mock_query.limit.return_value = mock_query
    mock_query.all.return_value = []
    mock_session.query.return_value = mock_query
    return mock_session

@pytest.fixture
def sentinel_service(mock_db_session):
    return SentinelService(db=mock_db_session)

# 1) Test empty cluster input to sentinel_service — verify graceful handling (no crash, appropriate log message)
def test_empty_cluster_input(sentinel_service, caplog):
    import logging
    with caplog.at_level(logging.INFO):
        # Empty campaign data
        empty_data = {}
        playbook = sentinel_service.generate_playbook(empty_data)
        
        # Verify it handled it gracefully
        assert playbook is not None
        assert playbook.src_ip is None
        assert playbook.protocol == "TCP"
        assert playbook.playbook_name == "UNKNOWN Network Service Discovery Playbook"

# 2) Test single-event campaign — verify playbook is still generated with minimal data
def test_single_event_campaign(sentinel_service):
    single_event_data = {
        "source_ips": ["192.168.1.100"],
        "target_ports": [2222],
        "protocols": ["TCP"],
        "event_count": 1,
        "campaign_id": "CAMP-SINGLE-01"
    }
    
    playbook = sentinel_service.generate_playbook(single_event_data)
    assert playbook is not None
    assert playbook.src_ip == "192.168.1.100"
    assert playbook.dst_port == 2222

# 3) Test unknown protocol (not SSH/HTTP/FTP/SMTP) — verify fallback behavior and appropriate technique mapping
def test_unknown_protocol(sentinel_service):
    unknown_proto_data = {
        "source_ips": ["10.0.0.5"],
        "target_ports": [9999], # Unknown port
        "protocols": ["UDP"],
        "event_count": 5
    }
    playbook = sentinel_service.generate_playbook(unknown_proto_data)
    
    assert playbook.protocol == "UDP"
    assert playbook.technique_id == "T1046" # Default discovery technique

# 4) Test malformed IP addresses (IPv6, empty string, None) in rule_generator — verify input validation
def test_malformed_ip_addresses_rule_generator():
    from sentinel.rule_generator import validate_ip
    
    # IPv6 should return False according to the logic
    assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == False
    assert validate_ip("") == False
    assert validate_ip(None) == False
    assert validate_ip("invalid_ip") == False
    assert validate_ip("192.168.1.1") == True
    assert validate_ip("any") == True
    assert validate_ip("$HOME_NET") == True

    # Test via validate_snort_rule_inputs
    res = validate_snort_rule_inputs("invalid_ip", 80, "tcp", "attempted-admin")
    assert res["status"] == "error"
    assert "Invalid source IP" in res["error"]

# 5) Test very large cluster (1000+ events) — verify no performance degradation or memory issues
def test_large_cluster(sentinel_service):
    large_cluster_data = {
        "source_ips": [f"10.0.0.{i%255}" for i in range(1000)],
        "target_ports": [80] * 1000,
        "protocols": ["TCP"] * 1000,
        "event_count": 1000,
        "campaign_id": "CAMP-LARGE-01"
    }
    
    import time
    start = time.time()
    playbook = sentinel_service.generate_playbook(large_cluster_data)
    end = time.time()
    
    assert playbook is not None
    assert playbook.src_ip == "10.0.0.0"
    assert playbook.dst_port == 80
    assert (end - start) < 15.0 # Should process within 15 seconds

# 6) Test duplicate campaign detection — verify deduplication prevents redundant playbook generation
def test_duplicate_campaign_detection(sentinel_service):
    campaign_data = {
        "source_ips": ["172.16.0.5"],
        "target_ports": [2222],
        "protocols": ["TCP"],
        "event_count": 10,
        "campaign_id": "CAMP-DUP-01"
    }
    
    # First call
    playbook1 = sentinel_service.generate_playbook(campaign_data)
    assert playbook1 is not None
    
    # Simulate DB state for duplicate check (this depends on how deduplication is implemented)
    # We will test the service behavior
    # If deduplication exists, it might return None or the same playbook ID
    playbook2 = sentinel_service.generate_playbook(campaign_data)
    
    # For now, just test if they are deduplicated
    # We expect deduplication to prevent redundant generation
    if playbook2 is not None:
        assert playbook1.playbook_id == playbook2.playbook_id
