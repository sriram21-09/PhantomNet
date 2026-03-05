from logging.logger import log_event
from datetime import datetime, timedelta
import collections

# Simple in-memory alert state
auth_failures = collections.defaultdict(list)

def check_auth_alerts(ip: str, success: bool):
    """
    Check if authentication attempts exceed safety thresholds.
    Threshold: >5 failures in 10 minutes.
    """
    if success:
        return
        
    now = datetime.now()
    # Add failure timestamp
    auth_failures[ip].append(now)
    
    # Prune old failures (>10 min)
    auth_failures[ip] = [t for t in auth_failures[ip] if now - t < timedelta(minutes=10)]
    
    # Check threshold
    if len(auth_failures[ip]) > 5:
        log_event(
            honeypot_type="ALERTER",
            event="security_alert_auth_threshold",
            level="ERROR",
            source_ip=ip,
            data={
                "msg": f"Threshold exceeded: {len(auth_failures[ip])} failures in 10 minutes",
                "ip": ip,
                "action": "flag_for_block"
            }
        )
        return True
    return False

def check_config_change_alert(user: str, resource: str):
    """Log an alert for any configuration change."""
    log_event(
        honeypot_type="ALERTER",
        event="security_alert_config_change",
        level="WARN",
        source_ip="INTERNAL",
        data={
            "user": user,
            "resource": resource,
            "timestamp": datetime.now().isoformat()
        }
    )
