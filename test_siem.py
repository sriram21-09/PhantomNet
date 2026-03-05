import os
import time
import requests
import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# --------- Mock Splunk/ELK Server ---------
class MockSIEMHandler(BaseHTTPRequestHandler):
    events_received = 0
    elk_events = 0
    splunk_events = 0

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        if self.path == '/services/collector/event':
            # Splunk HEC format
            lines = post_data.decode('utf-8').strip().split('\n')
            MockSIEMHandler.splunk_events += len(lines)
            MockSIEMHandler.events_received += len(lines)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"text": "Success"}')
        elif self.path == '/':
            # ELK format (assume JSON list)
            import json
            try:
                data = json.loads(post_data.decode('utf-8'))
                MockSIEMHandler.elk_events += len(data)
                MockSIEMHandler.events_received += len(data)
            except:
                pass
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass # Suppress HTTP logging

def run_server():
    server_address = ('', 8088)
    httpd = HTTPServer(server_address, MockSIEMHandler)
    httpd.serve_forever()

# Start background server
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
time.sleep(1) # wait for server to start

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from database.models import PacketLog
from services.universal_siem_exporter import get_siem_exporter

def test_export():
    print("Generating 1000 test events...")
    mock_events = []
    base_time = datetime.datetime.now(datetime.timezone.utc)
    for i in range(1000):
        pl = PacketLog(
            id=i+1,
            timestamp=base_time - datetime.timedelta(seconds=i),
            src_ip=f"192.168.1.{i%255}",
            dst_ip="10.0.0.1",
            src_port=10000 + i,
            dst_port=80,
            protocol="TCP",
            length=64,
            attack_type="HTTP_FLOOD" if i % 10 == 0 else None,
            threat_score=85.0 if i % 10 == 0 else 10.0,
            threat_level="HIGH" if i % 10 == 0 else "LOW",
            confidence=0.9,
            is_malicious=True if i % 10 == 0 else False,
            event=f"Test Event {i}"
        )
        mock_events.append(pl)

    # 1. Test Splunk Export
    print("\n--- Testing Splunk HEC Exporter ---")
    os.environ["SIEM_TYPE"] = "splunk"
    os.environ["SPLUNK_HEC_URL"] = "http://localhost:8088/services/collector/event"
    os.environ["SPLUNK_HEC_TOKEN"] = "test-token-1234"
    splunk_exporter = get_siem_exporter()
    
    start = time.time()
    # Send in batches of 100
    for i in range(0, 1000, 100):
        splunk_exporter.export_events(mock_events[i:i+100], "packet_log")
    splunk_elapsed = time.time() - start
    
    print(f"Splunk Export mapping and delivery complete.")
    print(f"Actual events received by Mock Splunk: {MockSIEMHandler.splunk_events}")
    print(f"Time taken to send 1000 Splunk events: {splunk_elapsed:.2f}s (Perf: {1000/splunk_elapsed:.2f} events/sec)")
    assert MockSIEMHandler.splunk_events == 1000, f"Expected 1000 Splunk events, got {MockSIEMHandler.splunk_events}"
    
    # 2. Test ELK Export
    print("\n--- Testing ELK / Logstash Exporter ---")
    os.environ["SIEM_TYPE"] = "elk"
    os.environ["LOGSTASH_URL"] = "http://localhost:8088/"
    elk_exporter = get_siem_exporter()
    
    start = time.time()
    for i in range(0, 1000, 100):
        elk_exporter.export_events(mock_events[i:i+100], "packet_log")
    elk_elapsed = time.time() - start
    
    print(f"ELK Export mapping and delivery complete.")
    print(f"Actual events received by Mock ELK: {MockSIEMHandler.elk_events}")
    print(f"Time taken to send 1000 ELK events: {elk_elapsed:.2f}s (Perf: {1000/elk_elapsed:.2f} events/sec)")
    assert MockSIEMHandler.elk_events == 1000, f"Expected 1000 ELK events, got {MockSIEMHandler.elk_events}"
    
    print("\n✅ All SIEM Export tests passed! No data loss verified. Factory pattern works.")

if __name__ == "__main__":
    test_export()
    # shutdown server
    sys.exit(0)
