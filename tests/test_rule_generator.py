import unittest
import yaml

from sentinel.rule_generator import (
    generate_snort_rule, 
    generate_sigma_rule,
    validate_ip, 
    validate_port,
    SNORT_RULE_TEMPLATE
)


def validate_snort_syntax(rule_str: str) -> dict:
    """
    Parses a Snort rule string and validates it against Snort 2.9/3.0 syntax rules.
    Raises ValueError on syntax violation.
    Returns a dictionary of parsed components.
    """
    if not rule_str:
        raise ValueError("Rule string is empty")
    
    rule_str = rule_str.strip()
    
    # Check that rule is enclosed in parentheses
    if not (rule_str.endswith(")") and "(" in rule_str):
        raise ValueError("Rule options must be enclosed in parentheses '(' and ')'")
    
    header_part, options_part = rule_str.split("(", 1)
    header_part = header_part.strip()
    options_part = options_part.rstrip(")").strip()
    
    # Validate header structure: action protocol src_ip src_port -> dst_ip dst_port
    header_tokens = header_part.split()
    if len(header_tokens) != 7:
        raise ValueError(f"Header has invalid number of tokens ({len(header_tokens)} instead of 7)")
        
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = header_tokens
    
    if action != "alert":
        raise ValueError(f"Invalid rule action: {action}")
        
    if protocol.lower() not in ("tcp", "udp", "icmp", "ip"):
        raise ValueError(f"Invalid protocol: {protocol}")
        
    if direction not in ("->", "<>"):
        raise ValueError(f"Invalid direction operator: {direction}")
        
    # Parse options, taking care of escaped semicolons '\;'
    options = []
    current_option = []
    i = 0
    while i < len(options_part):
        if options_part[i] == ';':
            # Check if escaped
            if i > 0 and options_part[i-1] == '\\':
                current_option.append(';')
            else:
                options.append("".join(current_option).strip())
                current_option = []
        else:
            current_option.append(options_part[i])
        i += 1
    
    if current_option and "".join(current_option).strip():
        raise ValueError("Options block is missing a terminating semicolon")
        
    parsed_options = {}
    for opt in options:
        if not opt:
            continue
        if ":" in opt:
            name, value = opt.split(":", 1)
            name = name.strip()
            value = value.strip()
            
            if name in parsed_options:
                if not isinstance(parsed_options[name], list):
                    parsed_options[name] = [parsed_options[name]]
                parsed_options[name].append(value)
            else:
                parsed_options[name] = value
        else:
            name = opt.strip()
            parsed_options[name] = True
            
    # Validate required options
    for req_key in ("msg", "flow", "threshold", "classtype", "reference", "sid", "rev"):
        if req_key not in parsed_options:
            raise ValueError(f"Missing required Snort option: {req_key}")
            
    # Validate msg field (must be wrapped in double quotes)
    msg_val = parsed_options["msg"]
    if not (msg_val.startswith('"') and msg_val.endswith('"')):
        raise ValueError("msg option value must be enclosed in double quotes")
        
    # Validate that double quotes inside msg are escaped
    inner_msg = msg_val[1:-1]
    j = 0
    while j < len(inner_msg):
        if inner_msg[j] == '"':
            bs_count = 0
            k = j - 1
            while k >= 0 and inner_msg[k] == '\\':
                bs_count += 1
                k -= 1
            if bs_count % 2 == 0:
                raise ValueError("Found unescaped double quote inside msg option value")
        j += 1
        
    # Validate sid is positive integer
    sid_val = parsed_options["sid"]
    try:
        sid_int = int(sid_val)
        if sid_int <= 0:
            raise ValueError(f"sid must be positive: {sid_val}")
    except ValueError:
        raise ValueError(f"sid is not a valid integer: {sid_val}")
        
    # Validate rev is positive integer
    rev_val = parsed_options["rev"]
    try:
        rev_int = int(rev_val)
        if rev_int <= 0:
            raise ValueError(f"rev must be positive: {rev_val}")
    except ValueError:
        raise ValueError(f"rev is not a valid integer: {rev_val}")
        
    return {
        "action": action,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "direction": direction,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "options": parsed_options
    }


class TestRuleGenerator(unittest.TestCase):
    
    def test_validate_ip(self):
        # Valid IPs
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.0/8"))
        self.assertTrue(validate_ip("any"))
        self.assertTrue(validate_ip("$EXTERNAL_NET"))
        self.assertTrue(validate_ip("$HOME_NET"))
        
        # Invalid IPs
        self.assertFalse(validate_ip("invalid_ip"))
        self.assertFalse(validate_ip("256.256.256.256"))
        self.assertFalse(validate_ip(None))
        self.assertFalse(validate_ip(123))

    def test_validate_port(self):
        # Valid ports
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port("443"))
        self.assertTrue(validate_port("any"))
        self.assertTrue(validate_port(0))
        self.assertTrue(validate_port(65535))
        
        # Invalid ports
        self.assertFalse(validate_port(-1))
        self.assertFalse(validate_port(65536))
        self.assertFalse(validate_port("invalid"))

    def test_generate_snort_rule_success(self):
        rule = generate_snort_rule(
            src_ip="$EXTERNAL_NET",
            dst_port=22,
            protocol="tcp",
            attack_desc="SSH Brute Force",
            technique_id="T1110",
            sid=1000001
        )
        # Verify it conforms to Snort syntax
        parsed = validate_snort_syntax(rule)
        
        self.assertEqual(parsed["action"], "alert")
        self.assertEqual(parsed["protocol"], "tcp")
        self.assertEqual(parsed["src_ip"], "$EXTERNAL_NET")
        self.assertEqual(parsed["dst_port"], "22")
        self.assertEqual(parsed["options"]["msg"], '"SSH Brute Force"')
        self.assertEqual(parsed["options"]["flow"], "to_server,established")
        self.assertEqual(parsed["options"]["threshold"], "type limit, track by_src, count 5, seconds 60")
        self.assertEqual(parsed["options"]["classtype"], "attempted-admin")
        self.assertEqual(parsed["options"]["reference"], "url,attack.mitre.org/techniques/T1110/")
        self.assertEqual(parsed["options"]["sid"], "1000001")
        self.assertEqual(parsed["options"]["rev"], "1")

    def test_generate_snort_rule_invalid_ip(self):
        with self.assertRaises(ValueError):
            generate_snort_rule("256.256.", 80, "tcp", "Desc", "T1234", 1)

    def test_generate_snort_rule_invalid_port(self):
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 99999, "tcp", "Desc", "T1234", 1)
            
    def test_generate_snort_rule_invalid_protocol(self):
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 80, "invalid_proto", "Desc", "T1234", 1)

    def test_template_fields(self):
        required_fields = ["{protocol}", "{src_ip}", "{dst_port}", "{attack_desc}", "{technique_id}", "{sid}"]
        for field in required_fields:
            self.assertIn(field, SNORT_RULE_TEMPLATE)

    def test_generate_snort_rule_auto_increment_sid(self):
        rule1 = generate_snort_rule(
            src_ip="$EXTERNAL_NET",
            dst_port=22,
            protocol="tcp",
            attack_desc="SSH Attack",
            technique_id="T1110"
        )
        parsed1 = validate_snort_syntax(rule1)
        sid1 = int(parsed1["options"]["sid"])
        
        rule2 = generate_snort_rule(
            src_ip="$EXTERNAL_NET",
            dst_port=22,
            protocol="tcp",
            attack_desc="SSH Attack",
            technique_id="T1110"
        )
        parsed2 = validate_snort_syntax(rule2)
        sid2 = int(parsed2["options"]["sid"])
        
        self.assertEqual(sid2, sid1 + 1)
        
    def test_generate_snort_rule_sid_jump_avoid_collision(self):
        custom_sid = 2000000
        rule_custom = generate_snort_rule(
            src_ip="$EXTERNAL_NET",
            dst_port=22,
            protocol="tcp",
            attack_desc="SSH Attack",
            technique_id="T1110",
            sid=custom_sid
        )
        parsed_custom = validate_snort_syntax(rule_custom)
        self.assertEqual(int(parsed_custom["options"]["sid"]), custom_sid)
        
        rule_next = generate_snort_rule(
            src_ip="$EXTERNAL_NET",
            dst_port=22,
            protocol="tcp",
            attack_desc="SSH Attack",
            technique_id="T1110"
        )
        parsed_next = validate_snort_syntax(rule_next)
        self.assertEqual(int(parsed_next["options"]["sid"]), custom_sid + 1)

    def test_generate_snort_rule_escaping(self):
        desc_with_special_chars = 'Attack with "quotes"; and \\backslashes\\.'
        rule = generate_snort_rule(
            src_ip="$EXTERNAL_NET",
            dst_port=80,
            protocol="tcp",
            attack_desc=desc_with_special_chars,
            technique_id="T1190"
        )
        parsed = validate_snort_syntax(rule)
        msg_val = parsed["options"]["msg"]
        
        self.assertIn('\\"', msg_val)
        self.assertIn('\\;', msg_val)
        self.assertIn('\\\\', msg_val)

    def test_generate_snort_rule_mitre_formatting(self):
        # 1. Plain technique ID
        rule1 = generate_snort_rule("any", 80, "tcp", "SQLi", "T1190")
        parsed1 = validate_snort_syntax(rule1)
        self.assertEqual(parsed1["options"]["reference"], "url,attack.mitre.org/techniques/T1190/")
        
        # 2. Sub-technique ID
        rule2 = generate_snort_rule("any", 80, "tcp", "Brute", "T1110.001")
        parsed2 = validate_snort_syntax(rule2)
        self.assertEqual(parsed2["options"]["reference"], "url,attack.mitre.org/techniques/T1110/001/")
        
        # 3. URL already
        rule3 = generate_snort_rule("any", 80, "tcp", "Brute", "https://attack.mitre.org/techniques/T1110/001/")
        parsed3 = validate_snort_syntax(rule3)
        self.assertEqual(parsed3["options"]["reference"], "url,attack.mitre.org/techniques/T1110/001/")

    def test_generate_sigma_rule_success(self):
        # Test basic successful Sigma rule generation
        title = "SSH Brute Force Attempt"
        logsource = {
            "category": "authentication",
            "product": "linux"
        }
        detection = {
            "selection": {
                "EventID": 4625,
                "SubStatus": "0xC000006A"
            },
            "condition": "selection"
        }
        severity = "HIGH"
        tags = ["honeypot", "ssh"]
        technique_id = "T1110.001"
        
        yaml_str = generate_sigma_rule(
            title=title,
            logsource=logsource,
            detection=detection,
            severity=severity,
            status="experimental",
            tags=tags,
            technique_id=technique_id
        )
        
        # Verify it parses as valid YAML
        parsed = yaml.safe_load(yaml_str)
        
        self.assertEqual(parsed["title"], title)
        self.assertEqual(parsed["status"], "experimental")
        self.assertEqual(parsed["logsource"], logsource)
        self.assertEqual(parsed["detection"], detection)
        self.assertEqual(parsed["level"], "high")
        self.assertIn("attack.t1110.001", parsed["tags"])
        self.assertIn("honeypot", parsed["tags"])
        self.assertIn("ssh", parsed["tags"])

    def test_generate_sigma_rule_invalid_inputs(self):
        # Test empty title
        with self.assertRaises(ValueError):
            generate_sigma_rule(
                title="",
                logsource={"category": "auth"},
                detection={"selection": {"EventID": 1}},
                severity="low"
            )
        # Test empty logsource
        with self.assertRaises(ValueError):
            generate_sigma_rule(
                title="Test Title",
                logsource={},
                detection={"selection": {"EventID": 1}},
                severity="low"
            )
        # Test empty detection
        with self.assertRaises(ValueError):
            generate_sigma_rule(
                title="Test Title",
                logsource={"category": "auth"},
                detection={},
                severity="low"
            )
        # Test empty severity
        with self.assertRaises(ValueError):
            generate_sigma_rule(
                title="Test Title",
                logsource={"category": "auth"},
                detection={"selection": {"EventID": 1}},
                severity=""
            )

    def test_generate_sigma_rule_severity_mapping(self):
        # Test various severity mappings
        logsource = {"category": "test"}
        detection = {"selection": {"field": "value"}}
        
        # Critical
        r_crit = generate_sigma_rule("Title", logsource, detection, "CRITICAL")
        self.assertEqual(yaml.safe_load(r_crit)["level"], "critical")
        
        # High
        r_high = generate_sigma_rule("Title", logsource, detection, "high ")
        self.assertEqual(yaml.safe_load(r_high)["level"], "high")
        
        # Medium
        r_med = generate_sigma_rule("Title", logsource, detection, "Medium")
        self.assertEqual(yaml.safe_load(r_med)["level"], "medium")
        
        # Low
        r_low = generate_sigma_rule("Title", logsource, detection, "LOW")
        self.assertEqual(yaml.safe_load(r_low)["level"], "low")
        
        # Info -> low
        r_info = generate_sigma_rule("Title", logsource, detection, "info")
        self.assertEqual(yaml.safe_load(r_info)["level"], "low")
        
        # Unknown -> medium
        r_unk = generate_sigma_rule("Title", logsource, detection, "unknown_severity")
        self.assertEqual(yaml.safe_load(r_unk)["level"], "medium")

    def test_generate_sigma_rule_detection_formatting(self):
        logsource = {"category": "test"}
        
        # Test case 1: Flat dict detection block automatically wrapped in selection
        flat_detection = {"CommandLine|contains": "whoami", "User": "root"}
        rule_flat = generate_sigma_rule("Title", logsource, flat_detection, "low")
        parsed_flat = yaml.safe_load(rule_flat)
        self.assertIn("selection", parsed_flat["detection"])
        self.assertEqual(parsed_flat["detection"]["selection"], flat_detection)
        self.assertEqual(parsed_flat["detection"]["condition"], "selection")
        
        # Test case 2: Structured selection but missing condition
        structured_no_cond = {"selection": {"CommandLine|contains": "whoami"}}
        rule_struct = generate_sigma_rule("Title", logsource, structured_no_cond, "low")
        parsed_struct = yaml.safe_load(rule_struct)
        self.assertEqual(parsed_struct["detection"]["condition"], "selection")
        
        # Test case 3: Structured multiple sections missing condition
        multi_no_cond = {
            "selection_1": {"CommandLine|contains": "whoami"},
            "selection_2": {"User": "root"}
        }
        rule_multi = generate_sigma_rule("Title", logsource, multi_no_cond, "low")
        parsed_multi = yaml.safe_load(rule_multi)
        # Condition should be "selection_1 or selection_2" or "selection_2 or selection_1"
        cond = parsed_multi["detection"]["condition"]
        self.assertTrue(cond in ("selection_1 or selection_2", "selection_2 or selection_1"))

    def test_generate_sigma_rule_tag_formatting(self):
        logsource = {"category": "test"}
        detection = {"selection": {"field": "value"}}
        
        # Test various tag inputs and MITRE technique normalization
        yaml_str = generate_sigma_rule(
            title="Title",
            logsource=logsource,
            detection=detection,
            severity="low",
            tags="honeypot, T1110.001, attack.t1059.007",
            technique_id="https://attack.mitre.org/techniques/T1190/"
        )
        parsed = yaml.safe_load(yaml_str)
        tags = parsed["tags"]
        
        self.assertIn("attack.t1190", tags)      # from technique_id URL
        self.assertIn("attack.t1110.001", tags)  # from tags (normalized)
        self.assertIn("attack.t1059.007", tags)  # from tags (normalized)
        self.assertIn("honeypot", tags)          # from tags (general tag lowercased)
        
        # Test comma/space separated string of tags
        yaml_str2 = generate_sigma_rule(
            title="Title",
            logsource=logsource,
            detection=detection,
            severity="low",
            tags="tag1 tag2,tag3",
        )
        parsed2 = yaml.safe_load(yaml_str2)
        self.assertEqual(parsed2["tags"], ["tag1", "tag2", "tag3"])


if __name__ == '__main__':
    unittest.main()

