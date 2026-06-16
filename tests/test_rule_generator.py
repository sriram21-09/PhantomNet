import unittest

from sentinel.rule_generator import (
    generate_snort_rule, 
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


if __name__ == '__main__':
    unittest.main()

