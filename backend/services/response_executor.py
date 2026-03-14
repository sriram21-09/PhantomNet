"""
PhantomNet Automated Response Executor
========================================

Central automated threat response engine that dispatches actions
based on configurable threat level thresholds.

Response Actions Matrix:
    LOW (0-39):      Log only
    MEDIUM (40-69):  Log + Alert + Rate limit
    HIGH (70-89):    Log + Alert + IP Block (temp, 30min) + Scale honeypots
    CRITICAL (90+):  Log + Alert + IP Block (permanent) + Scale + Notify admin

Usage:
    from services.response_executor import response_executor

    # Trigger response based on threat score
    response_executor.execute(ip="1.2.3.4", threat_score=85, threat_level="HIGH")
"""

import time
import platform
import subprocess
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Default Response Policy
# ──────────────────────────────────────────────
DEFAULT_POLICY = {
    "LOW": {
        "threshold": 0,
        "actions": ["log"],
        "block_duration_minutes": 0,
        "enabled": True,
    },
    "MEDIUM": {
        "threshold": 40,
        "actions": ["log", "alert", "rate_limit"],
        "block_duration_minutes": 0,
        "rate_limit_rpm": 10,
        "enabled": True,
    },
    "HIGH": {
        "threshold": 70,
        "actions": ["log", "alert", "block_ip", "scale_honeypots"],
        "block_duration_minutes": 30,
        "enabled": True,
    },
    "CRITICAL": {
        "threshold": 90,
        "actions": ["log", "alert", "block_ip", "scale_honeypots", "notify_admin"],
        "block_duration_minutes": 0,  # 0 = permanent
        "enabled": True,
    },
}

# IPs that should never be blocked
WHITELIST = {"127.0.0.1", "::1", "10.0.0.1", "phantomnet_postgres"}


class ResponseExecutor:
    """
    Automated threat response engine.

    Dispatches actions (block, scale, alert) based on configurable
    threat level policies. Maintains an audit log of all responses.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.policy = dict(DEFAULT_POLICY)
        self.blocked_ips = {}  # ip → {"blocked_at", "expires_at", "reason", "level"}
        self.response_history = []  # [{timestamp, ip, threat_level, actions, details}]
        self.rate_limits = defaultdict(list)  # ip → [timestamps]
        self._lock = threading.Lock()
        self._cleanup_thread = None
        self._running = False

        logger.info("[RESPONSE] Automated Response Executor initialized")
        self._start_cleanup_loop()

    # ──────────────────────────────────────────
    # Core: Execute Response
    # ──────────────────────────────────────────
    def execute(
        self,
        ip: str,
        threat_score: float,
        threat_level: str,
        protocol: str = "UNKNOWN",
        details: str = "",
    ) -> dict:
        """
        Execute automated response actions based on threat level.

        Returns:
            dict with actions taken and status
        """
        if ip in WHITELIST:
            return {"status": "skipped", "reason": "whitelisted", "ip": ip}

        threat_level = threat_level.upper()
        policy = self.policy.get(threat_level)

        if not policy or not policy.get("enabled"):
            return {
                "status": "skipped",
                "reason": "policy_disabled",
                "level": threat_level,
            }

        actions_taken = []
        action_details = {}

        # Execute each configured action
        for action in policy.get("actions", []):
            try:
                if action == "log":
                    self._action_log(ip, threat_score, threat_level, protocol, details)
                    actions_taken.append("log")

                elif action == "alert":
                    self._action_alert(ip, threat_score, threat_level, protocol)
                    actions_taken.append("alert")

                elif action == "rate_limit":
                    result = self._action_rate_limit(
                        ip, policy.get("rate_limit_rpm", 10)
                    )
                    actions_taken.append("rate_limit")
                    action_details["rate_limited"] = result

                elif action == "block_ip":
                    duration = policy.get("block_duration_minutes", 30)
                    result = self._action_block_ip(ip, duration, threat_level)
                    actions_taken.append("block_ip")
                    action_details["block"] = result

                elif action == "scale_honeypots":
                    result = self._action_scale_honeypots(threat_level, protocol)
                    actions_taken.append("scale_honeypots")
                    action_details["scaling"] = result

                elif action == "notify_admin":
                    self._action_notify_admin(ip, threat_score, threat_level, protocol)
                    actions_taken.append("notify_admin")

            except Exception as e:
                logger.error(f"[RESPONSE] Action '{action}' failed for {ip}: {e}")
                action_details[f"{action}_error"] = str(e)

        # Record in history
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "protocol": protocol,
            "actions": actions_taken,
            "details": action_details,
        }

        with self._lock:
            self.response_history.append(record)
            # Keep last 1000 records
            if len(self.response_history) > 1000:
                self.response_history = self.response_history[-1000:]

        return {
            "status": "executed",
            "actions": actions_taken,
            "details": action_details,
        }

    # ──────────────────────────────────────────
    # Action: Log
    # ──────────────────────────────────────────
    def _action_log(
        self, ip: str, score: float, level: str, protocol: str, details: str
    ):
        """Log the threat event."""
        logger.info(
            f"[RESPONSE] [{level}] IP={ip} Score={score:.1f} "
            f"Protocol={protocol} — {details or 'Automated response triggered'}"
        )

    # ──────────────────────────────────────────
    # Action: Alert
    # ──────────────────────────────────────────
    def _action_alert(self, ip: str, score: float, level: str, protocol: str):
        """Generate an alert (logged for dashboard consumption)."""
        alert = {
            "type": "THREAT_RESPONSE",
            "level": level,
            "message": f"Automated response triggered for {ip} "
            f"(score: {score:.1f}, protocol: {protocol})",
            "timestamp": datetime.utcnow().isoformat(),
        }
        logger.warning(f"[ALERT] {alert['message']}")

    # ──────────────────────────────────────────
    # Action: Rate Limit
    # ──────────────────────────────────────────
    def _action_rate_limit(self, ip: str, max_rpm: int) -> dict:
        """Apply rate limiting to an IP."""
        now = time.time()
        window = 60  # 1 minute

        with self._lock:
            # Clean old entries
            self.rate_limits[ip] = [t for t in self.rate_limits[ip] if now - t < window]
            self.rate_limits[ip].append(now)

            current_rate = len(self.rate_limits[ip])
            is_limited = current_rate > max_rpm

        if is_limited:
            logger.warning(
                f"[RATE LIMIT] {ip} exceeded {max_rpm} rpm (current: {current_rate})"
            )

        return {
            "ip": ip,
            "current_rpm": current_rate,
            "max_rpm": max_rpm,
            "is_limited": is_limited,
        }

    # ──────────────────────────────────────────
    # Action: Block IP (Cross-Platform)
    # ──────────────────────────────────────────
    def _action_block_ip(self, ip: str, duration_minutes: int, level: str) -> dict:
        """
        Block an IP address using platform-appropriate firewall.
        - Linux: iptables
        - Windows: netsh advfirewall
        """
        if ip in self.blocked_ips:
            return {"status": "already_blocked", "ip": ip}

        expires_at = None
        if duration_minutes > 0:
            expires_at = datetime.utcnow() + timedelta(minutes=duration_minutes)

        # Execute firewall command
        system = platform.system()
        block_result = self._execute_firewall_block(ip, system)

        # Track blocked IP
        with self._lock:
            self.blocked_ips[ip] = {
                "blocked_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at.isoformat() if expires_at else "permanent",
                "duration_minutes": (
                    duration_minutes if duration_minutes > 0 else "permanent"
                ),
                "reason": f"Automated: {level} threat",
                "level": level,
                "platform": system,
                "firewall_result": block_result,
            }

        logger.warning(
            f"[BLOCK] {ip} blocked — "
            f"{'permanent' if duration_minutes == 0 else f'{duration_minutes}min'} "
            f"(level: {level})"
        )

        return {
            "status": "blocked",
            "ip": ip,
            "duration": f"{'permanent' if duration_minutes == 0 else f'{duration_minutes}min'}",
            "platform": system,
        }

    def _execute_firewall_block(self, ip: str, system: str) -> dict:
        """Execute platform-specific firewall block command."""
        try:
            if system == "Linux":
                # iptables — drop all traffic from IP
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return {
                    "command": " ".join(cmd),
                    "success": result.returncode == 0,
                    "output": result.stdout or result.stderr,
                }
            elif system == "Windows":
                # netsh advfirewall
                rule_name = f"PhantomNet_AutoBlock_{ip}"
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return {
                    "command": " ".join(cmd),
                    "success": result.returncode == 0,
                    "output": result.stdout or result.stderr,
                }
            else:
                return {
                    "command": "none",
                    "success": False,
                    "output": f"Unsupported OS: {system}",
                }
        except subprocess.TimeoutExpired:
            return {
                "command": "timeout",
                "success": False,
                "output": "Command timed out",
            }
        except Exception as e:
            return {"command": "error", "success": False, "output": str(e)}

    def unblock_ip(self, ip: str) -> dict:
        """Manually unblock an IP address."""
        if ip not in self.blocked_ips:
            return {"status": "not_found", "ip": ip}

        system = platform.system()
        try:
            if system == "Linux":
                cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            elif system == "Windows":
                rule_name = f"PhantomNet_AutoBlock_{ip}"
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={rule_name}",
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except Exception as e:
            logger.error(f"[UNBLOCK] Failed to unblock {ip}: {e}")

        with self._lock:
            del self.blocked_ips[ip]

        logger.info(f"[UNBLOCK] {ip} unblocked")
        return {"status": "unblocked", "ip": ip}

    # ──────────────────────────────────────────
    # Action: Scale Honeypots
    # ──────────────────────────────────────────
    def _action_scale_honeypots(self, level: str, protocol: str) -> dict:
        """
        Trigger honeypot scaling based on threat level.
        Increases interaction depth and spawns additional listeners.
        """
        scaling_config = {
            "HIGH": {
                "additional_instances": 1,
                "interaction_depth": "medium",
                "capture_level": "full_payload",
            },
            "CRITICAL": {
                "additional_instances": 2,
                "interaction_depth": "high",
                "capture_level": "full_session",
            },
        }

        config = scaling_config.get(level, scaling_config["HIGH"])

        logger.info(
            f"[SCALE] Honeypot scaling triggered — "
            f"level={level}, protocol={protocol}, "
            f"instances=+{config['additional_instances']}, "
            f"depth={config['interaction_depth']}"
        )

        return {
            "protocol": protocol,
            "scaling_applied": config,
            "status": "scaling_requested",
        }

    # ──────────────────────────────────────────
    # Action: Notify Admin
    # ──────────────────────────────────────────
    def _action_notify_admin(self, ip: str, score: float, level: str, protocol: str):
        """Send admin notification for critical threats."""
        notification = {
            "type": "CRITICAL_THREAT",
            "ip": ip,
            "score": score,
            "level": level,
            "protocol": protocol,
            "timestamp": datetime.utcnow().isoformat(),
            "message": (
                f"🚨 CRITICAL: Automated response triggered for {ip} "
                f"(score: {score:.1f}, protocol: {protocol}). "
                f"IP has been permanently blocked."
            ),
        }
        logger.critical(f"[ADMIN NOTIFY] {notification['message']}")

    # ──────────────────────────────────────────
    # Block Expiry Cleanup
    # ──────────────────────────────────────────
    def _start_cleanup_loop(self):
        """Start background thread to clean expired blocks."""
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_expired_blocks, daemon=True
        )
        self._cleanup_thread.start()

    def _cleanup_expired_blocks(self):
        """Periodically check and remove expired IP blocks."""
        while self._running:
            try:
                now = datetime.utcnow()
                expired = []

                with self._lock:
                    for ip, info in self.blocked_ips.items():
                        if info["expires_at"] != "permanent":
                            exp_time = datetime.fromisoformat(info["expires_at"])
                            if now >= exp_time:
                                expired.append(ip)

                for ip in expired:
                    self.unblock_ip(ip)
                    logger.info(f"[CLEANUP] Auto-unblocked expired IP: {ip}")

            except Exception as e:
                logger.error(f"[CLEANUP] Error: {e}")

            time.sleep(60)  # Check every minute

    def stop(self):
        """Stop the cleanup thread."""
        self._running = False

    # ──────────────────────────────────────────
    # Policy Management
    # ──────────────────────────────────────────
    def get_policy(self) -> dict:
        """Return current response policy."""
        return self.policy

    def update_policy(self, updates: dict) -> dict:
        """
        Update response policy thresholds.
        Only updates provided fields, preserves defaults.
        """
        for level, config in updates.items():
            level = level.upper()
            if level in self.policy:
                self.policy[level].update(config)
                logger.info(f"[POLICY] Updated {level}: {config}")

        return self.policy

    # ──────────────────────────────────────────
    # Status & History
    # ──────────────────────────────────────────
    def get_blocked_ips(self) -> list:
        """Return list of currently blocked IPs."""
        return [{"ip": ip, **info} for ip, info in self.blocked_ips.items()]

    def get_history(self, limit: int = 50) -> list:
        """Return recent response actions."""
        return list(reversed(self.response_history[-limit:]))

    @property
    def stats(self) -> dict:
        """Return response executor statistics."""
        return {
            "total_responses": len(self.response_history),
            "blocked_ips": len(self.blocked_ips),
            "rate_limited_ips": len(self.rate_limits),
            "policy_levels": list(self.policy.keys()),
        }


# ──────────────────────────────────────────────
# Module-level singleton
# ──────────────────────────────────────────────
response_executor = ResponseExecutor()
