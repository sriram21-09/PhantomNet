import yaml
import logging
import time
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from .firewall import FirewallService
from .alert_manager import alert_manager
from .threat_intel import threat_intel_service
from database.database import SessionLocal
from database.models import Alert # We will use Alert for logging playbook actions for now

logger = logging.getLogger("playbook_engine")

class PlaybookEngine:
    """
    Automated Incident Response Playbook Execution Engine.
    Parses YAML playbooks and executes defined actions with rollback support.
    """

    def __init__(self):
        self.execution_history = []
        self.active_executions = {}

    def load_playbook(self, file_path: str) -> Dict[str, Any]:
        """Loads a playbook from a YAML file."""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load playbook from {file_path}: {e}")
            raise

    async def execute_playbook(self, playbook_data: Dict[str, Any], trigger_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a playbook based on the provided trigger context.
        """
        playbook_name = playbook_data.get("name", "Unknown Playbook")
        execution_id = f"{playbook_name}_{int(time.time())}"
        
        logger.info(f"[*] Starting execution of playbook: {playbook_name} (ID: {execution_id})")
        
        execution_state = {
            "execution_id": execution_id,
            "playbook_name": playbook_name,
            "start_time": datetime.utcnow().isoformat(),
            "status": "in-progress",
            "actions_executed": [],
            "context": trigger_context
        }
        
        start_ts = time.time()
        
        try:
            for action in playbook_data.get("actions", []):
                action_name = action.get("name")
                action_type = action.get("type")
                params = self._resolve_params(action.get("params", {}), trigger_context)
                rollback_action = action.get("rollback")

                logger.info(f"Executing action: {action_name} ({action_type})")
                
                try:
                    result = await self._run_action(action_type, params)
                    execution_state["actions_executed"].append({
                        "name": action_name,
                        "type": action_type,
                        "status": "completed",
                        "result": result,
                        "rollback": rollback_action,
                        "params": params
                    })
                except Exception as e:
                    logger.error(f"Action {action_name} failed: {e}")
                    execution_state["actions_executed"].append({
                        "name": action_name,
                        "type": action_type,
                        "status": "failed",
                        "error": str(e)
                    })
                    # Trigger Rollback
                    await self._rollback(execution_state["actions_executed"])
                    execution_state["status"] = "failed"
                    execution_state["error"] = str(e)
                    break
            else:
                execution_state["status"] = "completed"

        except Exception as e:
            logger.error(f"Playbook execution error: {e}")
            execution_state["status"] = "failed"
            execution_state["error"] = str(e)

        execution_state["end_time"] = datetime.utcnow().isoformat()
        execution_state["duration"] = time.time() - start_ts
        
        self.execution_history.append(execution_state)
        logger.info(f"[+] Playbook {playbook_name} finished with status: {execution_state['status']}")
        
        return execution_state

    def _resolve_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves placeholders like ${source_ip} in action parameters."""
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                key = v[2:-1]
                resolved[k] = context.get(key, v)
            else:
                resolved[k] = v
        return resolved

    async def _run_action(self, action_type: str, params: Dict[str, Any]) -> Any:
        """Dispatches action execution to the appropriate service."""
        if action_type == "block_ip":
            return FirewallService.block_ip(params.get("ip"))
        
        elif action_type == "send_alert":
            return alert_manager.create_alert(
                level=params.get("level", "INFO"),
                alert_type="PLAYBOOK_ACTION",
                description=params.get("message"),
                source_ip=params.get("ip")
            )
        
        elif action_type == "query_threat_intel":
            return await threat_intel_service.enrich_ip(params.get("ip"))
        
        elif action_type == "tarpit":
            # Simulation of tarpit
            logger.info(f"Simulating tarpit for {params.get('ip')} with {params.get('delay_ms')}ms delay")
            await asyncio.sleep(params.get("delay_ms", 1000) / 1000.0)
            return {"status": "success", "delay": params.get("delay_ms")}
        
        elif action_type == "create_ticket":
            # Mocking ticket creation
            logger.info(f"Creating {params.get('system')} ticket: {params.get('summary')}")
            return {"status": "success", "ticket_id": f"INC-{int(time.time())}"}
        
        elif action_type == "deploy_honeypot":
            logger.info(f"Deploying {params.get('count')} honeypots of type {params.get('type')}")
            return {"status": "success", "nodes": params.get("count")}

        elif action_type == "capture_packets":
            logger.info(f"Starting packet capture for {params.get('ip')} for {params.get('duration')}")
            return {"status": "success", "file": f"capture_{params.get('ip')}.pcap"}

        elif action_type == "isolate_host":
            logger.warning(f"Isolating host: {params.get('ip')}")
            return {"status": "success", "message": f"Host {params.get('ip')} isolated."}

        else:
            logger.warning(f"Unknown action type: {action_type}")
            return {"status": "skipped", "message": "Unknown action type"}

    async def _rollback(self, executed_actions: List[Dict[str, Any]]):
        """Reverts actions in reverse order."""
        logger.info("!!! Rolling back executed actions !!!")
        for action in reversed(executed_actions):
            if action["status"] == "completed" and action.get("rollback"):
                rb_type = action["rollback"]
                params = action.get("params", {})
                logger.info(f"Rolling back: {action['name']} using {rb_type}")
                
                try:
                    if rb_type == "unblock_ip":
                        # We need a way to unblock IP via FirewallService
                        system = "Windows" # Defaulting for simplicity
                        # FirewallService doesn't have unblock_ip yet, let's use response_executor if needed or add it
                        from .response_executor import response_executor
                        response_executor.unblock_ip(params.get("ip"))
                    elif rb_type == "reconnect_host":
                        logger.info(f"Reconnecting host: {params.get('ip')}")
                except Exception as e:
                    logger.error(f"Rollback of {action['name']} failed: {e}")

# Singleton
playbook_engine = PlaybookEngine()
