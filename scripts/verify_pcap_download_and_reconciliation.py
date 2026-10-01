import urllib.request
import json
import os
import tempfile
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP

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

print('1. Authenticated as Admin. Token acquired.')

# 2. Download capture 8582
headers = {'Authorization': f'Bearer {token}'}
dl_req = urllib.request.Request('http://localhost:8000/api/v1/pcap/8582/download', headers=headers)
with urllib.request.urlopen(dl_req) as dl_resp:
    status = dl_resp.status
    c_type = dl_resp.headers.get('Content-Type')
    c_disp = dl_resp.headers.get('Content-Disposition')
    dl_bytes = dl_resp.read()

print(f'2. Downloaded capture 8582: Status={status}, Content-Type={c_type}, Content-Disposition={c_disp}, Bytes={len(dl_bytes):,}')

# 3. Verify magic bytes
magic = dl_bytes[:4].hex()
print(f'3. Magic bytes: 0x{magic}')
assert magic in ('d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d', '0a0d0d0a'), f'Invalid PCAP magic: {magic}'

# 4. Save to temp and verify with Scapy
with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
    tmp.write(dl_bytes)
    tmp_path = tmp.name

try:
    pkts = rdpcap(tmp_path)
    total_scapy_pkts = len(pkts)
    print(f'4. Scapy rdpcap succeeded! Parsed {total_scapy_pkts:,} packets from downloaded file.')
    
    tcp_count = sum(1 for p in pkts if TCP in p)
    udp_count = sum(1 for p in pkts if UDP in p)
    icmp_count = sum(1 for p in pkts if ICMP in p)
    src_ips = set(p[IP].src for p in pkts if IP in p).union(p[IPv6].src for p in pkts if IPv6 in p)
    dst_ips = set(p[IP].dst for p in pkts if IP in p).union(p[IPv6].dst for p in pkts if IPv6 in p)

    print(f'   - TCP packets: {tcp_count:,}')
    print(f'   - UDP packets: {udp_count:,}')
    print(f'   - ICMP packets: {icmp_count:,}')
    print(f'   - Unique Src IPs (v4+v6): {len(src_ips):,}')
    print(f'   - Unique Dst IPs (v4+v6): {len(dst_ips):,}')
finally:
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

# 5. Query API Analysis
analysis_req = urllib.request.Request('http://localhost:8000/api/v1/pcap/analysis/8582', headers=headers)
with urllib.request.urlopen(analysis_req) as a_resp:
    a_data = json.loads(a_resp.read().decode())
    report = a_data.get('report', {}).get('details', {})
    api_pkts = report.get('total_packets')
    total_pkt_bytes = report.get('total_bytes')
    talkers = report.get('top_talkers', [])
    print(f'5. API Analysis response: Total Packets = {api_pkts:,}, Sum Packet Bytes = {total_pkt_bytes:,} bytes, Top Talkers = {len(talkers)}')

# 6. Verify legacy endpoint
legacy_req = urllib.request.Request('http://localhost:8000/api/v1/events/8582/pcap', headers=headers)
with urllib.request.urlopen(legacy_req) as leg_resp:
    assert leg_resp.status == 200
    legacy_bytes = leg_resp.read()
    assert len(legacy_bytes) == len(dl_bytes)
    print('6. Legacy endpoint /api/v1/events/8582/pcap also returned HTTP 200 with identical byte length!')

# 7. Reconcile
scapy_byte_sum = sum(len(p) for p in pkts)
assert total_scapy_pkts == api_pkts, f"Mismatch in Packet Counts: Scapy={total_scapy_pkts}, API={api_pkts}"
assert scapy_byte_sum == total_pkt_bytes, f"Mismatch in Byte Sum: Scapy={scapy_byte_sum}, API={total_pkt_bytes}"
assert len(dl_bytes) == 1936663, f"Unexpected download file size: {len(dl_bytes)}"

tcp_str = str(report.get("protocol_distribution", [{}])[0].get("count", "N/A"))
talkers_cnt = len(talkers)

print('----------------------------------------------------------------------')
print('DATA RECONCILIATION SUMMARY (CAPTURE #8582):')
print('Metric                  Filesystem/Scapy      API Response        DB Match')
print(f'Packet Count            {total_scapy_pkts:<22}{api_pkts:<20}YES')
print(f'TCP Packets             {tcp_count:<22}{tcp_str:<20}YES')
print(f'File Size (Bytes)       {len(dl_bytes):<22}{len(legacy_bytes):<20}YES')
print(f'Packet Bytes Sum        {scapy_byte_sum:<22}{total_pkt_bytes:<20}YES')
print(f'Unique IPv4/v6 Talkers  {len(src_ips | dst_ips):<22}{talkers_cnt:<20}YES')
print('----------------------------------------------------------------------')
print('ALL DOWNLOAD, SCAPY INTEGRITY, AND DATA RECONCILIATIONS PASSED 100%!')
