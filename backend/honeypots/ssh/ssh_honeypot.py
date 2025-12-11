import time
import os

log_path = "/logs/ssh/honeypot.log"
os.makedirs(os.path.dirname(log_path), exist_ok=True)

while True:
    with open(log_path, "a") as f:
        f.write("SSH Honeypot alive\n")
    time.sleep(5)
