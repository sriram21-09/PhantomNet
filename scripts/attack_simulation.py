import subprocess
from datetime import datetime

TARGET = "localhost"
PORT = "2222"

def run_nmap_scan():
    print("[*] Starting SSH reconnaissance scan")
    print(f"[*] Target: {TARGET}:{PORT}")

    start_time = datetime.now()
    print(f"[*] Scan started at: {start_time}")

    command = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    "-p", PORT, TARGET
]

    result = subprocess.run(command, capture_output=True, text=True)

    end_time = datetime.now()
    print(f"[*] Scan completed at: {end_time}")

    print("\n--- Nmap Output ---")
    print(result.stdout)

if __name__ == "__main__":
    run_nmap_scan()
