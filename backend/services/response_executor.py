import subprocess
import logging
import os
import platform

logger = logging.getLogger("response_executor")
logger.setLevel(logging.INFO)

class ResponseExecutor:
    def __init__(self):
        self.system = platform.system()
        # Mapping threat levels to actions
        self.response_matrix = {
            "INFO": ["LOG"],
            "WARNING": ["LOG", "ALERT"],
            "HIGH": ["LOG", "ALERT", "BLOCK_IP"],
            "CRITICAL": ["LOG", "ALERT", "BLOCK_IP", "SCALE_HONEYPOT"]
        }

    def execute_response(self, level: str, source_ip: str = None, attack_type: str = None):
        """
        Executes a series of response actions based on the threat level.
        """
        actions = self.response_matrix.get(level.upper(), ["LOG"])
        logger.info(f"Executing response for level {level} (IP: {source_ip}, Attack: {attack_type}). Actions: {actions}")

        for action in actions:
            if action == "BLOCK_IP" and source_ip:
                self._block_ip(source_ip)
            elif action == "SCALE_HONEYPOT" and attack_type:
                self._scale_honeypots(attack_type)
            # LOG and ALERT are handled by the calling service (ThreatAnalyzer/AlertManager)

    def _block_ip(self, ip: str):
        """
        Blocks an IP using 'iptables' (Linux) or 'netsh' (Windows).
        """
        logger.info(f"Attempting to block IP: {ip}")
        
        if self.system == "Windows":
            # Fallback for Windows (using the Netsh command identified earlier)
            rule_name = f"PhantomNet_Block_{ip}"
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ]
        else:
            # Standard Linux implementation as requested (iptables)
            command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

        try:
            # We use shell=True for netsh if needed, but list format is safer
            subprocess.run(command, capture_output=True, text=True, check=True)
            logger.info(f"Successfully blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error blocking IP {ip}: {e}")

    def _scale_honeypots(self, attack_type: str):
        """
        Scales up honeypot instances based on the attack type.
        """
        # Determine service name from attack type
        service_map = {
            "SSH": "ssh_honeypot",
            "HTTP": "http_honeypot",
            "FTP": "ftp_honeypot",
            "SMTP": "smtp-honeypot"
        }
        
        # Default to a generic one or determine from attack_type string
        service_name = None
        for key, val in service_map.items():
            if key in attack_type.upper():
                service_name = val
                break
        
        if not service_name:
            logger.warning(f"No specific honeypot to scale for attack type: {attack_type}. Scaling HTTP as default.")
            service_name = "http_honeypot"

        logger.info(f"Scaling up service: {service_name}")
        
        # Command to scale using docker-compose
        # Note: This assumes docker-compose.yml is in the root and we are running from there or backend
        # We'll try to find the project root
        command = ["docker-compose", "up", "-d", "--scale", f"{service_name}=2"]
        
        try:
            # Run in the project directory
            # For simplicity in this env, we'll try running it and log output
            subprocess.run(command, capture_output=True, text=True, check=True)
            logger.info(f"Successfully scaled {service_name} to 2 instances.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to scale {service_name}: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error scaling {service_name}: {e}")

# Singleton instance
response_executor = ResponseExecutor()
