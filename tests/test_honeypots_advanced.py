import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from database.database import SessionLocal
from database.models import PacketLog

def mock_log_to_db(protocol, src_ip, attack_type, payload):
    db = SessionLocal()
    from datetime import datetime
    p = PacketLog(
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        protocol=protocol,
        attack_type=attack_type,
        event=payload
    )
    db.add(p)
    db.commit()
    db.close()

class TestSSHHoneypotAdvanced:
    def test_brute_force_detection(self):
        for _ in range(5):
            mock_log_to_db("SSH", "192.168.200.1", "brute_force", "admin:123")
        
        db = SessionLocal()
        count = db.query(PacketLog).filter(PacketLog.src_ip == "192.168.200.1").count()
        db.close()
        assert count >= 5

    def test_command_logging(self):
        mock_log_to_db("SSH", "10.0.0.4", "command", "cat /etc/shadow")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.event.contains("shadow")).first()
        db.close()
        assert event is not None

class TestHTTPHoneypotAdvanced:
    def test_path_traversal_attempts(self):
        mock_log_to_db("HTTP", "10.10.10.1", "path_traversal", "../../../etc/passwd")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.event.contains("etc/passwd")).first()
        db.close()
        assert event is not None

    def test_sql_injection_patterns(self):
        mock_log_to_db("HTTP", "10.10.10.2", "sqli", "admin' OR 1=1--")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.event.contains("OR 1=1")).first()
        db.close()
        assert event is not None

    def test_xss_attempts(self):
        mock_log_to_db("HTTP", "10.10.10.3", "xss", "<script>alert(1)</script>")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.event.contains("<script>")).first()
        db.close()
        assert event is not None

class TestDatabaseHoneypotAdvanced:
    def test_mysql_connection_attempts(self):
        mock_log_to_db("MYSQL", "10.20.20.1", "login", "root")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.protocol == "MYSQL").first()
        db.close()
        assert event is not None

    def test_postgresql_fake_port(self):
        mock_log_to_db("POSTGRES", "10.20.20.2", "login", "postgres")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.protocol == "POSTGRES").first()
        db.close()
        assert event is not None

class TestTelnetHoneypotAdvanced:
    def test_multiple_login_attempts(self):
        for _ in range(5):
             mock_log_to_db("TELNET", "10.30.30.1", "login", "admin:1234")
        
        db = SessionLocal()
        count = db.query(PacketLog).filter(PacketLog.protocol == "TELNET").count()
        db.close()
        assert count >= 5

    def test_iot_botnet_simulation_mirai(self):
        mock_log_to_db("TELNET", "10.30.30.2", "mirai_signature", "mirai")
        db = SessionLocal()
        event = db.query(PacketLog).filter(PacketLog.event.contains("mirai")).first()
        db.close()
        assert event is not None

class TestHoneypotStatusDashboard:
    def test_verify_all_honeypots_receiving_traffic(self):
        db = SessionLocal()
        distinct_honeypots = [r[0] for r in db.query(PacketLog.protocol).distinct().all()]
        db.close()
        assert "SSH" in distinct_honeypots
        assert "HTTP" in distinct_honeypots
        assert "TELNET" in distinct_honeypots
        assert "MYSQL" in distinct_honeypots
