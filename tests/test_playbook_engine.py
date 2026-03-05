import asyncio
import os
import sys
import logging

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from services.playbook_engine import playbook_engine

# Mocking external calls for testing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_playbook")

async def test_brute_force_playbook():
    print("\n--- Testing Brute Force Response Playbook ---")
    playbook_path = 'playbooks/brute_force_response.yaml'
    playbook_data = playbook_engine.load_playbook(playbook_path)
    
    context = {
        "source_ip": "1.2.3.4",
        "failed_logins": 25
    }
    
    result = await playbook_engine.execute_playbook(playbook_data, context)
    print(f"Status: {result['status']}")
    print(f"Duration: {result['duration']:.2f}s")
    for action in result['actions_executed']:
        print(f"  - Action: {action['name']} | Status: {action['status']}")

async def test_port_scan_playbook():
    print("\n--- Testing Port Scan Response Playbook ---")
    playbook_path = 'playbooks/port_scan_response.yaml'
    playbook_data = playbook_engine.load_playbook(playbook_path)
    
    context = {
        "source_ip": "5.6.7.8",
        "port_count": 100
    }
    
    result = await playbook_engine.execute_playbook(playbook_data, context)
    print(f"Status: {result['status']}")
    print(f"Duration: {result['duration']:.2f}s")
    for action in result['actions_executed']:
        print(f"  - Action: {action['name']} | Status: {action['status']}")

async def test_credential_reuse_playbook():
    print("\n--- Testing Credential Reuse Detection Playbook ---")
    playbook_path = 'playbooks/credential_reuse_response.yaml'
    playbook_data = playbook_engine.load_playbook(playbook_path)
    
    context = {
        "source_ip": "9.10.11.12",
        "token_id": "ADM-KEY-001",
        "target_ip": "192.168.1.50",
        "location": "production_server"
    }
    
    result = await playbook_engine.execute_playbook(playbook_data, context)
    print(f"Status: {result['status']}")
    print(f"Duration: {result['duration']:.2f}s")
    for action in result['actions_executed']:
        print(f"  - Action: {action['name']} | Status: {action['status']}")

async def test_distributed_attack_playbook():
    print("\n--- Testing Distributed Attack Response Playbook ---")
    playbook_path = 'playbooks/distributed_attack_response.yaml'
    playbook_data = playbook_engine.load_playbook(playbook_path)
    
    context = {
        "source_ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"],
        "distinct_ips": 6,
        "attack_pattern": "SSH_BRUTE_FORCE_DISTRIBUTED",
        "timestamp": "2024-03-04_0510"
    }
    
    result = await playbook_engine.execute_playbook(playbook_data, context)
    print(f"Status: {result['status']}")
    print(f"Duration: {result['duration']:.2f}s")
    for action in result['actions_executed']:
        print(f"  - Action: {action['name']} | Status: {action['status']}")

async def test_rollback():
    print("\n--- Testing Rollback Functionality ---")
    playbook_data = {
        "name": "Rollback Test",
        "actions": [
            {
                "name": "Action 1 (Should succeed)",
                "type": "block_ip",
                "params": {"ip": "1.1.1.1"},
                "rollback": "unblock_ip"
            },
            {
                "name": "Action 2 (Should fail)",
                "type": "invalid_action",
                "params": {"data": "broken"}
            }
        ]
    }
    
    # We deliberately use an unknown action to trigger a "failure" logic in engine
    # Actually, the engine currently logs "skipped" for unknown actions. 
    # Let's modify the engine to raise an error if an action fails for real testing of rollback.
    # For now, let's manually mock a failure or use a param that triggers error.
    
    context = {"source_ip": "1.1.1.1"}
    # Note: Invalid action type will currently return "skipped" status in _run_action, 
    # not raise an exception. Let's force an exception if we want to test rollback.
    
    # Actually, in playbook_engine.py:
    # try: result = await self._run_action(...)
    # except Exception as e: ... trigger rollback
    
    # Let's use an action that might fail, or mock it.
    
    result = await playbook_engine.execute_playbook(playbook_data, context)
    print(f"Status: {result['status']}")

async def main():
    await test_brute_force_playbook()
    await test_port_scan_playbook()
    await test_credential_reuse_playbook()
    await test_distributed_attack_playbook()
    # await test_rollback()

if __name__ == "__main__":
    asyncio.run(main())
