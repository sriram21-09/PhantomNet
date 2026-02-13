import subprocess
import platform

class FirewallService:
    @staticmethod
    def block_ip(ip_address: str):
        """
        Executes a Windows 'netsh' command to block an IP via the Firewall.
        """
        system = platform.system()
        
        # Simple check to ensure we are on Windows
        if system != "Windows":
            return {"status": "error", "message": "Active Defense only works on Windows."}

        rule_name = f"PhantomNet_Block_{ip_address}"
        
        # The Windows Command:
        # netsh advfirewall firewall add rule name="..." dir=in action=block remoteip=...
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]

        try:
            # Run the command silently
            subprocess.run(command, capture_output=True, text=True, check=True)
            return {"status": "success", "message": f"Target {ip_address} successfully neutralized."}
        except subprocess.CalledProcessError as e:
            # If it fails, usually means 'Run as Admin' is needed
            return {"status": "error", "message": f"Access Denied: Run terminal as Administrator. ({e.stderr})"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
