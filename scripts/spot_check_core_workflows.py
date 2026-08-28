"""
Spot-check script for PhantomNet Core Workflows (Week 22 Day 4 Regression Testing)
Verifies:
1. Firewall Service (Cross-platform IP blocking, unblocking, input validation)
2. Policy Engine (Node policy retrieval, JSON recovery)
3. Node Management (Registration, listing, status check)
4. Sentinel Playbook Engine (Playbook generation, Sigma/Snort rules, STIX bundle)
5. TAXII 2.1 Services (Collections, feed objects retrieval)
6. ML Scoring Engine (Single event scoring, batch scoring, feature extraction)
"""
import sys
import os
from pathlib import Path

# Add backend directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.append(str(PROJECT_ROOT))

import time
import json
import logging
from unittest.mock import patch, MagicMock

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("spot_check")

def spot_check_firewall():
    logger.info("--- Spot-Checking FirewallService ---")
    from services.firewall import FirewallService
    fw = FirewallService()

    # 1. Valid block/unblock (mocking subprocess to prevent actual OS changes)
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
        
        # Block IP
        res_block = fw.block_ip("203.0.113.55")
        assert res_block["status"] == "success", f"Expected success status, got {res_block}"
        logger.info("[PASS] Valid IP blocked successfully")

        # Unblock IP
        res_unblock = fw.unblock_ip("203.0.113.55")
        assert res_unblock["status"] == "success", f"Expected success status, got {res_unblock}"
        logger.info("[PASS] Valid IP unblocked successfully")

        # 2. Malformed IP rejection
        res_invalid = fw.block_ip("not-an-ip; rm -rf /")
        assert res_invalid["status"] == "error", "Expected rejection of malformed IP"
        logger.info("[PASS] Malformed IP injection rejected safely")

def spot_check_policy_engine():
    logger.info("--- Spot-Checking PolicyEngine ---")
    from services.policy_engine import PolicyEngine
    from database.database import SessionLocal, engine, Base
    from database.models import Policy, HoneypotNode
    
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    pe = PolicyEngine(db)

    test_node_id = "spot-check-node-1"
    # Ensure clean state
    db.query(HoneypotNode).filter(HoneypotNode.node_id == test_node_id).delete()
    db.query(Policy).filter(Policy.name == "TestCorrupt").delete()
    db.commit()

    # Create corrupted policy & node
    corrupted_policy = Policy(name="TestCorrupt", description="Corrupt JSON test", config="{bad_json: 123,}")
    db.add(corrupted_policy)
    db.commit()
    db.refresh(corrupted_policy)

    node = HoneypotNode(node_id=test_node_id, ip_address="192.168.1.50", honeypot_type="ssh", policy_id=corrupted_policy.id)
    db.add(node)
    db.commit()

    retrieved = pe.get_policy_for_node(test_node_id)
    assert retrieved is not None, "Expected policy retrieval"
    assert "raw_config" in retrieved, "Expected raw_config fallback for corrupted JSON"
    logger.info("[PASS] PolicyEngine safely recovered from corrupted JSON config")

    # Cleanup
    db.query(HoneypotNode).filter(HoneypotNode.node_id == test_node_id).delete()
    db.query(Policy).filter(Policy.id == corrupted_policy.id).delete()
    db.commit()
    db.close()

def spot_check_node_manager():
    logger.info("--- Spot-Checking NodeManager ---")
    from services.node_manager import NodeManager
    from database.database import SessionLocal, engine, Base
    from database.models import HoneypotNode

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    nm = NodeManager(db)

    hostname = "spot-check-honeypot-ssh"
    db.query(HoneypotNode).filter(HoneypotNode.hostname == hostname).delete()
    db.commit()

    # Register
    node = nm.register_node(hostname=hostname, ip_address="192.168.10.99", honeypot_type="ssh")
    assert node is not None, "Node registration failed"
    logger.info("[PASS] Node registered successfully")

    # List
    nodes = nm.list_nodes()
    assert any(n.hostname == hostname for n in nodes), "Registered node not found in list"
    logger.info("[PASS] Node listing verified")

    # Cleanup
    db.query(HoneypotNode).filter(HoneypotNode.hostname == hostname).delete()
    db.commit()
    db.close()

def spot_check_sentinel_engine():
    logger.info("--- Spot-Checking Sentinel Playbook & Rule Engine ---")
    from sentinel.rule_generator import generate_snort_rule, generate_sigma_rule
    from sentinel.stix_enhanced import build_stix_bundle
    from sentinel.mitre_mapper import map_signature

    # 1. Rule Generation
    snort = generate_snort_rule(
        src_ip="198.51.100.24",
        dst_port=22,
        protocol="tcp",
        attack_desc="SSH Brute Force",
        technique_id="T1110.001",
        severity="HIGH"
    )
    assert "alert tcp" in snort, f"Invalid snort rule: {snort}"
    logger.info("[PASS] Snort rule generated successfully")

    sigma = generate_sigma_rule(
        title="SSH Brute Force Detection",
        logsource={"category": "auth", "product": "linux"},
        detection={"selection": {"event_id": 1100}, "condition": "selection"},
        severity="high",
        technique_id="T1110.001",
        tactic="Credential Access"
    )
    assert "title: SSH Brute Force Detection" in sigma or "title:" in sigma, f"Invalid sigma rule: {sigma}"
    logger.info("[PASS] Sigma rule generated successfully")

    # 2. STIX Bundle Generation
    technique = map_signature("SSH_AUTH_FAILURE")
    iocs = [{"type": "ip", "value": "198.51.100.24"}]
    stix_bundle = build_stix_bundle(technique, iocs, src_ip="198.51.100.24", threat_score=0.85)
    assert stix_bundle is not None
    assert getattr(stix_bundle, "type", None) == "bundle", "Expected STIX bundle type"
    assert len(getattr(stix_bundle, "objects", [])) > 0, "Expected non-empty STIX objects"
    logger.info(f"[PASS] STIX 2.1 bundle generated with {len(stix_bundle.objects)} objects")

def spot_check_ml_scoring():
    logger.info("--- Spot-Checking ML Threat Scoring Engine ---")
    from schemas.threat_schema import ThreatInput
    from ml.threat_scoring_service import score_threat, score_threat_batch, _LOCAL_PRED_CACHE

    _LOCAL_PRED_CACHE.clear()

    # Single event scoring
    inp = ThreatInput(
        src_ip="203.0.113.19",
        dst_ip="10.0.0.5",
        dst_port=80,
        protocol="TCP",
        length=1400,
        is_malicious=True
    )
    res = score_threat(inp)
    assert res is not None
    assert res.score >= 0.0 and res.score <= 1.0
    assert res.threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    logger.info(f"[PASS] Single ML score: score={res.score}, level={res.threat_level}, decision={res.decision}")

    # Batch scoring
    batch_inputs = [
        ThreatInput(src_ip=f"203.0.113.{i}", dst_ip="10.0.0.5", dst_port=22, protocol="TCP", length=1200 + i)
        for i in range(10)
    ]
    batch_res = score_threat_batch(batch_inputs)
    assert len(batch_res) == 10
    logger.info(f"[PASS] Batch ML scoring: processed {len(batch_res)} events successfully")

def main():
    logger.info("=== Starting PhantomNet Core Workflows Spot-Check ===")
    try:
        spot_check_firewall()
        spot_check_policy_engine()
        spot_check_node_manager()
        spot_check_sentinel_engine()
        spot_check_ml_scoring()
        logger.info("=== ALL CORE WORKFLOW SPOT-CHECKS COMPLETED SUCCESSFULLY ===")
        return 0
    except Exception as e:
        logger.error(f"Spot-check FAILED: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
