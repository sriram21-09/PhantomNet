import ipaddress
import logging
import platform
import subprocess

logger = logging.getLogger("firewall_service")


class FirewallService:
    @staticmethod
    def block_ip(ip_address: str) -> dict:
        """
        Executes a platform-specific firewall command to block an IP address.
        Supports Windows (netsh) and Linux (iptables).
        """
        ip_clean = ip_address.strip()
        try:
            ipaddress.ip_address(ip_clean)
        except ValueError:
            return {"status": "error", "message": "Invalid IP address format."}

        system = platform.system()
        rule_name = f"PhantomNet_Block_{ip_clean}"

        try:
            if system == "Windows":
                command = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip_clean}",
                ]
                subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            elif system == "Linux":
                command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_clean, "-j", "DROP"]
                subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported platform: {system}",
                }

            return {
                "status": "success",
                "message": f"Target {ip_clean} successfully neutralized.",
            }
        except subprocess.CalledProcessError as e:
            logger.error("Firewall block error: %s", e.stderr)
            return {
                "status": "error",
                "message": f"Firewall command failed: Administrator / root privileges required. ({e.stderr.strip()})",
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Firewall command timed out."}
        except Exception as e:
            logger.error("Unexpected error in FirewallService.block_ip: %s", e)
            return {"status": "error", "message": str(e)}

    @staticmethod
    def unblock_ip(ip_address: str) -> dict:
        """
        Executes a platform-specific firewall command to unblock an IP address.
        Supports Windows (netsh) and Linux (iptables).
        """
        ip_clean = ip_address.strip()
        try:
            ipaddress.ip_address(ip_clean)
        except ValueError:
            return {"status": "error", "message": "Invalid IP address format."}

        system = platform.system()
        rule_name = f"PhantomNet_Block_{ip_clean}"

        try:
            if system == "Windows":
                command = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={rule_name}",
                ]
                subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            elif system == "Linux":
                command = ["sudo", "iptables", "-D", "INPUT", "-s", ip_clean, "-j", "DROP"]
                subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported platform: {system}",
                }

            return {
                "status": "success",
                "message": f"Target {ip_clean} successfully unblocked.",
            }
        except subprocess.CalledProcessError as e:
            logger.warning("Firewall unblock warning: %s", e.stderr)
            return {
                "status": "error",
                "message": f"Firewall unblock command failed: ({e.stderr.strip()})",
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Firewall unblock command timed out."}
        except Exception as e:
            logger.error("Unexpected error in FirewallService.unblock_ip: %s", e)
            return {"status": "error", "message": str(e)}
