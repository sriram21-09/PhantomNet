"""
verify_rule_generator.py
------------------------
End-to-end deliverable verification script.
Checks every task and deliverable item from the Week-13 Day-5 spec.
"""
import re
import sys
import yaml

# ── make sure the project root is on sys.path ──────────────────────────────
import os
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sentinel.rule_generator import (
    SNORT_RULE_TEMPLATE,
    escape_snort_string,
    format_mitre_url,
    clean_and_format_tag,
    map_severity_to_level,
    generate_snort_rule,
    generate_sigma_rule,
    validate_ip,
    validate_port,
    generate_rules_for_campaign,
)

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = []


def check(label, condition, detail=""):
    tag = PASS if condition else FAIL
    suffix = f"  [{detail}]" if detail else ""
    print(f"  {tag}  {label}{suffix}")
    if not condition:
        failures.append(label)


# ═══════════════════════════════════════════════════════════════════════════
# TASK 1  File existence & imports
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("TASK 1  — tests/test_rule_generator.py  &  sentinel/rule_generator.py")
print("="*65)

test_path = os.path.join(PROJECT_ROOT, "tests", "test_rule_generator.py")
impl_path = os.path.join(PROJECT_ROOT, "sentinel", "rule_generator.py")

check("tests/test_rule_generator.py exists", os.path.isfile(test_path))
check("sentinel/rule_generator.py exists",   os.path.isfile(impl_path))

symbols = [
    "SNORT_RULE_TEMPLATE", "escape_snort_string", "format_mitre_url",
    "clean_and_format_tag", "map_severity_to_level", "generate_snort_rule",
    "generate_sigma_rule", "validate_ip", "validate_port",
    "generate_rules_for_campaign",
]
for sym in symbols:
    check(f"symbol '{sym}' importable", sym in dir(__import__("sentinel.rule_generator", fromlist=[sym])))

# ═══════════════════════════════════════════════════════════════════════════
# TASK 2  Snort rule syntax validity
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("TASK 2  — Snort rule syntax (semicolons, parentheses, SID)")
print("="*65)

# SNORT_RULE_TEMPLATE placeholders
for ph in ["{protocol}", "{src_ip}", "{dst_port}", "{attack_desc}", "{technique_id}", "{sid}"]:
    check(f"SNORT_RULE_TEMPLATE contains {ph}", ph in SNORT_RULE_TEMPLATE)
check("SNORT_RULE_TEMPLATE has '('",  "("  in SNORT_RULE_TEMPLATE)
check("SNORT_RULE_TEMPLATE ends ')'", SNORT_RULE_TEMPLATE.strip().endswith(")"))

# Generated rule structure
rule = generate_snort_rule("192.168.1.1", 22, "tcp", "SSH Brute Force", "T1110.001", sid=1000001)
check("rule starts with 'alert'",            rule.startswith("alert"))
check("rule contains '('",                  "(" in rule)
check("rule ends with ')'",                  rule.strip().endswith(")"))
opts_block = rule[rule.index("(")+1:-1].strip()
check("options block ends with ';'",         opts_block.endswith(";"))
check("msg field is double-quoted",          'msg:"' in rule)
check("SID 1000001 present in rule",         "sid:1000001;" in rule)
check("rev:1 present",                       "rev:1;" in rule)
check("flow option present",                 "flow:to_server,established;" in rule)
check("threshold option present",            "threshold:type limit" in rule)
check("classtype option present",            "classtype:attempted-admin;" in rule)
check("reference option present",            "reference:url,attack.mitre.org" in rule)

# Semicolon escaping
rule_semi = generate_snort_rule("any", 80, "tcp", "End; payload", "T1190")
check("semicolon in msg is escaped (\\;)",   r"\;" in rule_semi)

# Backslash escaping
rule_bs = generate_snort_rule("any", 80, "tcp", "Path\\to\\evil", "T1190")
check("backslash in msg is doubled (\\\\)",  r"\\" in rule_bs)

# Double-quote escaping
rule_dq = generate_snort_rule("any", 80, "tcp", 'Desc "quoted"', "T1190")
check('double-quote in msg is escaped (\\")', '\\"' in rule_dq)

# SID validation
try:
    generate_snort_rule("any", 80, "tcp", "t", "T1234", sid=0)
    check("sid=0 raises ValueError", False)
except ValueError:
    check("sid=0 raises ValueError", True)

try:
    generate_snort_rule("any", 80, "tcp", "t", "T1234", sid=-5)
    check("sid<0 raises ValueError", False)
except ValueError:
    check("sid<0 raises ValueError", True)

# ═══════════════════════════════════════════════════════════════════════════
# TASK 3  Sigma YAML parsing
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("TASK 3  — Sigma rule YAML parsing (valid YAML, correct schema)")
print("="*65)

LS  = {"category": "authentication", "product": "linux"}
DET = {"selection": {"EventID": 4625}, "condition": "selection"}

sigma_str = generate_sigma_rule("SSH Brute Force", LS, DET, "HIGH")

# Valid YAML
try:
    sigma_data = yaml.safe_load(sigma_str)
    check("output is valid YAML",          isinstance(sigma_data, dict))
except yaml.YAMLError as e:
    check("output is valid YAML",          False, str(e))

# Required schema keys
for key in ("title", "status", "logsource", "detection", "level"):
    check(f"required key '{key}' present", key in sigma_data)

# detection must have 'condition'
check("detection has 'condition' key",     "condition" in sigma_data.get("detection", {}))

# level values
for sev, expected in [("CRITICAL","critical"), ("HIGH","high"), ("MEDIUM","medium"),
                      ("LOW","low"), ("INFO","low"), ("random","medium")]:
    data = yaml.safe_load(generate_sigma_rule("T", LS, DET, sev))
    check(f"severity '{sev}' -> level '{expected}'", data["level"] == expected)

# status lowercased
data = yaml.safe_load(generate_sigma_rule("T", LS, DET, "HIGH", status="Experimental"))
check("status lowercased ('experimental')", data["status"] == "experimental")

# tags
data = yaml.safe_load(generate_sigma_rule("T", LS, DET, "HIGH", technique_id="T1110.001"))
check("technique_id added as attack tag",  "attack.t1110.001" in data.get("tags", []))

# flat detection wrapped
flat = {"CommandLine|contains": "whoami", "User": "root"}
data = yaml.safe_load(generate_sigma_rule("T", LS, flat, "LOW"))
check("flat detection wrapped in 'selection'", "selection" in data["detection"])
check("flat detection gets 'condition'",        data["detection"]["condition"] == "selection")

# invalid inputs raise ValueError
for label, args in [
    ("empty title",     ("",  LS, DET, "LOW")),
    ("None title",      (None,LS, DET, "LOW")),
    ("empty logsource", ("T", {}, DET, "LOW")),
    ("empty detection", ("T", LS, {},  "LOW")),
    ("empty severity",  ("T", LS, DET, ""  )),
]:
    try:
        generate_sigma_rule(*args)
        check(f"ValueError on {label}", False)
    except ValueError:
        check(f"ValueError on {label}", True)

# ═══════════════════════════════════════════════════════════════════════════
# TASK 4  Edge cases
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("TASK 4  — Edge cases: empty IP, unknown protocol, port 0")
print("="*65)

# Empty IP
check("validate_ip('') returns False",  not validate_ip(""))
try:
    generate_snort_rule("", 80, "tcp", "t", "T1234")
    check("empty IP raises ValueError", False)
except ValueError:
    check("empty IP raises ValueError", True)

# None IP
check("validate_ip(None) returns False", not validate_ip(None))
try:
    generate_snort_rule(None, 80, "tcp", "t", "T1234")
    check("None IP raises ValueError", False)
except ValueError:
    check("None IP raises ValueError", True)

# Unknown protocols
for proto in ("ftp", "http", "ssh", "smtp"):
    try:
        generate_snort_rule("any", 80, proto, "t", "T1234")
        check(f"unknown protocol '{proto}' raises ValueError", False)
    except ValueError:
        check(f"unknown protocol '{proto}' raises ValueError", True)

# Port 0 is valid
check("validate_port(0) returns True",    validate_port(0))
check("validate_port('0') returns True",  validate_port("0"))
rule_p0 = generate_snort_rule("any", 0, "tcp", "Port0 test", "T1234")
check("port 0 generates valid rule",      "any 0 " in rule_p0 or " 0 (" in rule_p0 or "-> any 0" in rule_p0)

# Port -1 invalid
check("validate_port(-1) returns False",  not validate_port(-1))
try:
    generate_snort_rule("any", -1, "tcp", "t", "T1234")
    check("port -1 raises ValueError", False)
except ValueError:
    check("port -1 raises ValueError", True)

# Port 65536 invalid
check("validate_port(65536) returns False", not validate_port(65536))

# Campaign-level filtering
result = generate_rules_for_campaign(
    {"unique_sources": ["not-an-ip", "1.1.1.1"], "target_ports": [8080], "protocols": ["tcp"]}, None)
check("invalid IP filtered; valid survives (1 rule)", result["metadata"]["snort_rule_count"] == 1)

result = generate_rules_for_campaign(
    {"unique_sources": ["1.1.1.1"], "target_ports": [80], "protocols": ["http", "ssh", "tcp"]}, None)
check("unknown protocols filtered; tcp survives (1 rule)", result["metadata"]["snort_rule_count"] == 1)

result = generate_rules_for_campaign(
    {"unique_sources": ["not-ip","also-bad"], "target_ports": [80], "protocols": ["tcp"]}, None)
check("all invalid IPs fall back to 'any'",
      generate_snort_rule.__module__ and
      result["snort_rules_list"][0].split()[2] == "any")

result = generate_rules_for_campaign(
    {"unique_sources": ["1.1.1.1"], "target_ports": [80], "protocols": ["ftp","ssh"]}, None)
check("all invalid protocols fall back to 'ip'",
      result["snort_rules_list"][0].split()[1] == "ip")

# ═══════════════════════════════════════════════════════════════════════════
# TASK 5  SID auto-increment uniqueness
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("TASK 5  — SID auto-increment uniqueness")
print("="*65)

import threading

def _get_sid(rule_str):
    m = re.search(r"sid:(\d+);", rule_str)
    return int(m.group(1)) if m else None

# 100 sequential calls → all unique
sids_seq = [_get_sid(generate_snort_rule("any", 80, "tcp", "t", "T1234")) for _ in range(100)]
check("100 sequential auto-SIDs are unique",              len(sids_seq) == len(set(sids_seq)))
check("100 sequential auto-SIDs are strictly increasing", all(a < b for a, b in zip(sids_seq, sids_seq[1:])))

# Concurrent calls → all unique
results_c, lock_c, errors_c = [], threading.Lock(), []
def worker():
    try:
        sid = _get_sid(generate_snort_rule("any", 80, "tcp", "thread", "T1234"))
        with lock_c:
            results_c.append(sid)
    except Exception as e:
        with lock_c:
            errors_c.append(str(e))

threads = [threading.Thread(target=worker) for _ in range(40)]
for t in threads: t.start()
for t in threads: t.join()
check("40 concurrent auto-SIDs are unique",   len(results_c) == len(set(results_c)))
check("no errors in concurrent SID threads",  len(errors_c) == 0)

# Explicit SID advances counter
high = 9_000_000
generate_snort_rule("any", 80, "tcp", "explicit", "T1234", sid=high)
next_rule = generate_snort_rule("any", 80, "tcp", "next", "T1234")
next_sid = _get_sid(next_rule)
check(f"explicit SID {high} advances counter (next={high+1})", next_sid == high + 1)

# ═══════════════════════════════════════════════════════════════════════════
# DELIVERABLE — test count in test file
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("DELIVERABLE — Comprehensive test suite count")
print("="*65)

with open(test_path) as fh:
    src = fh.read()
test_methods = re.findall(r"def (test_\w+)", src)
test_classes = re.findall(r"class (Test\w+)", src)
check(f"test file has >= 6 test classes ({len(test_classes)} found)",  len(test_classes) >= 6)
check(f"test file has >= 80 test methods ({len(test_methods)} found)", len(test_methods) >= 80)

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "="*65)
total_checks = sum(1 for line in open(__file__, encoding="utf-8", errors="replace") if "check(" in line)
print(f"SUMMARY:  {len(failures)} failure(s) out of all checks")
if failures:
    print("\nFailed checks:")
    for f in failures:
        print(f"  ✗  {f}")
    sys.exit(1)
else:
    print("\n  ALL DELIVERABLES VERIFIED — ZERO ERRORS")
print("="*65)
