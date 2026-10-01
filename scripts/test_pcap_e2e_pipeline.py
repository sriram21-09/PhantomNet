import urllib.request
import json
import os
import time
import tempfile
from scapy.all import rdpcap, IP, TCP, UDP

# 1. Login
admin_pass = os.environ.get("PHANTOMNET_ADMIN_PASSWORD", "PhantomNet_SecAdmin_2026!")
login_req = urllib.request.Request(
    'http://localhost:8000/api/v1/admin/login',
    data=json.dumps({'username': 'admin', 'password': admin_pass}).encode(),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(login_req) as resp:
    login_data = json.loads(resp.read().decode())
    token = login_data['access_token']

headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
print('[PASS] Step 1: Admin authenticated and JWT token issued.')

# 2. Check an existing event/packet log to trigger capture
# Or use ID 8582 or trigger a fresh capture with duration=2
test_cap_id = 99999
cap_trigger_req = urllib.request.Request(
    f'http://localhost:8000/api/v1/pcap/capture/8582?duration=2',
    headers=headers,
    method='POST'
)
with urllib.request.urlopen(cap_trigger_req) as trig_resp:
    trig_data = json.loads(trig_resp.read().decode())
    assert trig_resp.status == 200
    print(f'[PASS] Step 2: Triggered live capture via POST /api/v1/pcap/capture/8582: {trig_data.get("status")}')

# Wait for 3 seconds for capture thread to complete and write metadata
time.sleep(3.5)

# 3. Verify capture status
status_req = urllib.request.Request(
    'http://localhost:8000/api/v1/pcap/capture/8582/status',
    headers=headers
)
with urllib.request.urlopen(status_req) as st_resp:
    st_data = json.loads(st_resp.read().decode())
    print(f'[PASS] Step 3: Capture status queried: {st_data.get("capture", {}).get("status")}')

# 4. Verify capture appears in GET /api/v1/pcap/captures
list_req = urllib.request.Request(
    'http://localhost:8000/api/v1/pcap/captures?search=8582&limit=5',
    headers=headers
)
with urllib.request.urlopen(list_req) as l_resp:
    l_data = json.loads(l_resp.read().decode())
    assert l_data.get('total') >= 1
    found = any(c['id'] == 8582 for c in l_data.get('captures', []))
    assert found, "Capture 8582 not found in catalog listing"
    print(f'[PASS] Step 4: Capture 8582 listed in GET /api/v1/pcap/captures catalog with metadata.')

# 5. Load Analysis
analysis_req = urllib.request.Request(
    'http://localhost:8000/api/v1/pcap/analysis/8582',
    headers=headers
)
with urllib.request.urlopen(analysis_req) as a_resp:
    a_data = json.loads(a_resp.read().decode())
    rep = a_data.get('report', {}).get('details', {})
    pkts = rep.get('total_packets')
    assert pkts > 0
    print(f'[PASS] Step 5: Real Scapy analysis retrieved: {pkts:,} packets analyzed.')

# 6. Download capture
dl_req = urllib.request.Request(
    'http://localhost:8000/api/v1/pcap/8582/download',
    headers=headers
)
with urllib.request.urlopen(dl_req) as dl_resp:
    dl_bytes = dl_resp.read()
    assert dl_resp.status == 200
    assert len(dl_bytes) > 0
    print(f'[PASS] Step 6: Downloaded PCAP binary bytes: {len(dl_bytes):,} bytes.')

# 7. Scapy parse downloaded bytes
with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
    tmp.write(dl_bytes)
    tmp_path = tmp.name

try:
    scapy_pkts = rdpcap(tmp_path)
    assert len(scapy_pkts) == pkts
    print(f'[PASS] Step 7: Scapy validated downloaded file integrity ({len(scapy_pkts):,} packets parsed successfully).')
finally:
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

print('======================================================================')
print('COMPLETE END-TO-END PIPELINE AUDIT VERIFIED!')
print('======================================================================')
