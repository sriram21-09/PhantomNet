import sys, os
sys.path.insert(0, os.path.join('backend'))

from sentinel.rule_generator import (
    generate_snort_rule, generate_sigma_rule,
    SEVERITY_TO_PRIORITY, ATTACK_TYPE_TO_CLASSTYPE,
    validate_ip, validate_port, _SID_FILE_PATH
)

print('=== VERIFICATION: Sentinel Rule Generation ===')
print()

# 1. SID file path check
print(f'[1] SID persistence file: {_SID_FILE_PATH}')
sid_exists = os.path.exists(_SID_FILE_PATH)
print(f'    File exists: {sid_exists}')
if sid_exists:
    with open(_SID_FILE_PATH) as f:
        print(f'    Current SID value: {f.read().strip()}')

print()

# 2. Severity to Priority map
print('[2] Severity -> Priority mapping:')
for sev, pri in SEVERITY_TO_PRIORITY.items():
    print(f'    {sev} -> priority:{pri}')

print()

# 3. Attack Type -> Classtype map sample
print('[3] Attack-type -> Classtype mapping (sample):')
sample_keys = ['ssh_brute_force', 'sqli_attempt', 'port_scan', 'data_exfiltration']
for k in sample_keys:
    print(f'    {k} -> {ATTACK_TYPE_TO_CLASSTYPE.get(k, "NOT FOUND")}')

print()

# 4. Snort rules
print('[4] Snort rule examples:')
attacks = [
    ('SSH Brute Force',  '192.168.10.50', 2222, 'tcp', 'T1110.001', 'attempted-admin',        'HIGH'),
    ('HTTP SQL Inject',  '10.0.5.101',    8080, 'tcp', 'T1190',     'web-application-attack', 'CRITICAL'),
    ('Port Scan',        '172.16.20.200', 80,   'tcp', 'T1046',     'attempted-recon',         'LOW'),
    ('FTP Exfil',        '203.0.113.15',  21,   'tcp', 'T1048.003', 'successful-admin',        'CRITICAL'),
]
for label, ip, port, proto, tid, ct, sev in attacks:
    rule = generate_snort_rule(
        src_ip=ip, dst_port=port, protocol=proto,
        attack_desc=f'PhantomNet: {label} from {ip} port {port}',
        technique_id=tid, classtype=ct, severity=sev
    )
    assert 'alert' in rule and 'sid:' in rule and 'reference:' in rule
    print(f'    [{label}] OK - rule length={len(rule)} chars')

print()

# 5. Sigma rules
print('[5] Sigma rule examples:')
sigma_attacks = [
    ('SSH Brute Force',  '192.168.10.50', [2222],     'T1110.001', 'Credential Access', 'HIGH'),
    ('HTTP SQLi',        '10.0.5.101',    [8080],     'T1190',     'Initial Access',    'CRITICAL'),
    ('Port Scan',        '172.16.20.200', [21,22,80], 'T1046',     'Discovery',          'LOW'),
    ('FTP Exfiltration', '203.0.113.15',  [21],       'T1048.003', 'Exfiltration',      'CRITICAL'),
]
for label, ip, ports, tid, tactic, sev in sigma_attacks:
    rule = generate_sigma_rule(
        title=f'PhantomNet: {label}',
        logsource={'category': 'network_traffic', 'product': 'phantomnet'},
        detection={'selection': {'src_ip': [ip], 'dst_port': ports}, 'condition': 'selection'},
        severity=sev, technique_id=tid, tactic=tactic
    )
    assert 'title:' in rule and 'logsource:' in rule and 'detection:' in rule and 'tags:' in rule
    print(f'    [{label}] OK - rule length={len(rule)} chars')

print()

# 6. Validate docs file exists
doc_path = os.path.join('docs', 'rule_generation.md')
assert os.path.exists(doc_path), 'docs/rule_generation.md MISSING!'
size = os.path.getsize(doc_path)
print(f'[6] docs/rule_generation.md: EXISTS ({size} bytes)')

print()
print('=== ALL CHECKS PASSED ===')
