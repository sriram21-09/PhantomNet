"""
Response Mapping Configuration
This file acts as a static contract for mapping abstract decision responses
to concrete system actions.
"""

RESPONSE_MAP = {
    "LOG": {
        "action": "log",
        "description": "Log event only",
        "priority": 0
    },
    "THROTTLE": {
        "action": "rate_limit",
        "limit_rate": "10/m",
        "burst": 5,
        "description": "Degrade connection quality",
        "priority": 1
    },
    "DECEIVE": {
        "action": "redirect",
        "target": "honeypot_cluster_1",
        "description": "Route to high-interaction honeypot",
        "priority": 2
    },
    "BLOCK": {
        "action": "drop",
        "firewall_rule": "DROP_IMMEDIATE",
        "duration_seconds": 3600,
        "description": "Sever connection immediately",
        "priority": 3
    }
}
