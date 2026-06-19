import threading
import unittest
import yaml

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


# ---------------------------------------------------------------------------
# Helper: lightweight Snort rule parser / validator
# ---------------------------------------------------------------------------

def parse_snort_rule(rule_str):
    if not rule_str or not rule_str.strip():
        raise ValueError("Rule string is empty")
    rule_str = rule_str.strip()
    try:
        paren_open = rule_str.index("(")
    except ValueError:
        raise ValueError("Rule options block must contain '('")
    if not rule_str.endswith(")"):
        raise ValueError("Rule options block must end with ')'")
    header_part  = rule_str[:paren_open].strip()
    options_part = rule_str[paren_open + 1 : -1].strip()
    tokens = header_part.split()
    if len(tokens) != 7:
        raise ValueError("Header must have exactly 7 tokens, got %d: %s" % (len(tokens), tokens))
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = tokens
    if action != "alert":
        raise ValueError("Rule action must be alert, got %s" % action)
    if protocol.lower() not in ("tcp", "udp", "icmp", "ip"):
        raise ValueError("Invalid protocol: %s" % protocol)
    if direction not in ("->", "<>"):
        raise ValueError("Invalid direction: %s" % direction)
    raw_options = []
    current = []
    i = 0
    while i < len(options_part):
        ch = options_part[i]
        if ch == ";" and (i == 0 or options_part[i - 1] != "\\"):
            raw_options.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    leftover = "".join(current).strip()
    if leftover:
        raise ValueError("Options block missing terminating semicolon. Leftover: %r" % leftover)
    parsed_options = {}
    for opt in raw_options:
        if not opt:
            continue
        if ":" in opt:
            name, value = opt.split(":", 1)
            name = name.strip()
            value = value.strip()
        else:
            name = opt.strip()
            value = True
        if name in parsed_options:
            existing = parsed_options[name]
            if not isinstance(existing, list):
                parsed_options[name] = [existing]
            parsed_options[name].append(value)
        else:
            parsed_options[name] = value
    required = ("msg", "flow", "threshold", "classtype", "reference", "sid", "rev")
    for req in required:
        if req not in parsed_options:
            raise ValueError("Missing required Snort option: %r" % req)
    msg_val = parsed_options["msg"]
    if not (msg_val.startswith('"') and msg_val.endswith('"')):
        raise ValueError("msg value must be enclosed in double-quotes")
    inner = msg_val[1:-1]
    j = 0
    while j < len(inner):
        if inner[j] == '"':
            backslashes = 0
            k = j - 1
            while k >= 0 and inner[k] == "\\":
                backslashes += 1
                k -= 1
            if backslashes % 2 == 0:
                raise ValueError("Unescaped double-quote found inside msg")
        j += 1
    try:
        sid_int = int(parsed_options["sid"])
        if sid_int <= 0:
            raise ValueError("sid must be > 0, got %d" % sid_int)
    except (ValueError, TypeError):
        raise ValueError("sid is not a valid positive integer: %s" % parsed_options["sid"])
    try:
        rev_int = int(parsed_options["rev"])
        if rev_int <= 0:
            raise ValueError("rev must be > 0, got %d" % rev_int)
    except (ValueError, TypeError):
        raise ValueError("rev is not a valid positive integer: %s" % parsed_options["rev"])
    return {
        "action": action, "protocol": protocol, "src_ip": src_ip,
        "src_port": src_port, "direction": direction,
        "dst_ip": dst_ip, "dst_port": dst_port, "options": parsed_options,
    }


SIGMA_REQUIRED_KEYS = {"title", "status", "logsource", "detection", "level"}


def parse_sigma_yaml(yaml_str):
    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError as exc:
        raise ValueError("Sigma rule is not valid YAML: %s" % exc) from exc
    if not isinstance(data, dict):
        raise ValueError("Sigma rule YAML must produce a top-level mapping")
    missing = SIGMA_REQUIRED_KEYS - data.keys()
    if missing:
        raise ValueError("Sigma rule is missing required keys: %s" % missing)
    if data["level"] not in ("critical", "high", "medium", "low"):
        raise ValueError("Invalid Sigma level: %s" % data["level"])
    if "detection" not in data or "condition" not in data["detection"]:
        raise ValueError("Sigma rule detection block must contain a condition key")
    return data


# ===========================================================================
# Task 2/4: Helper unit tests
# ===========================================================================

class TestHelpers(unittest.TestCase):
    """Unit tests for internal helper functions."""

    def test_escape_backslash(self):
        self.assertEqual(escape_snort_string("a\\b"), "a\\\\b")

    def test_escape_semicolon(self):
        self.assertIn("\\;", escape_snort_string("end;here"))

    def test_escape_combined(self):
        result = escape_snort_string("a; path\\file")
        self.assertIn("\\;", result)
        self.assertIn("\\\\", result)

    def test_escape_non_string_returns_empty(self):
        self.assertEqual(escape_snort_string(None), "")
        self.assertEqual(escape_snort_string(123), "")

    def test_format_mitre_plain_id(self):
        self.assertEqual(format_mitre_url("T1190"), "T1190/")

    def test_format_mitre_sub_technique(self):
        self.assertEqual(format_mitre_url("T1110.001"), "T1110/001/")

    def test_format_mitre_full_url(self):
        self.assertEqual(
            format_mitre_url("https://attack.mitre.org/techniques/T1110/001/"),
            "T1110/001/",
        )

    def test_format_mitre_empty_returns_empty(self):
        self.assertEqual(format_mitre_url(""), "")
        self.assertEqual(format_mitre_url(None), "")

    def test_clean_tag_technique(self):
        self.assertEqual(clean_and_format_tag("T1190"), "attack.t1190")

    def test_clean_tag_sub_technique(self):
        self.assertEqual(clean_and_format_tag("T1110.001"), "attack.t1110.001")

    def test_clean_tag_url(self):
        self.assertEqual(
            clean_and_format_tag("https://attack.mitre.org/techniques/T1190/"),
            "attack.t1190",
        )

    def test_clean_tag_plain_string(self):
        self.assertEqual(clean_and_format_tag("honeypot"), "honeypot")

    def test_clean_tag_non_string_returns_empty(self):
        self.assertEqual(clean_and_format_tag(None), "")
        self.assertEqual(clean_and_format_tag(42), "")

    def test_severity_critical(self):
        self.assertEqual(map_severity_to_level("CRITICAL"), "critical")

    def test_severity_high(self):
        self.assertEqual(map_severity_to_level("HIGH"), "high")

    def test_severity_medium(self):
        self.assertEqual(map_severity_to_level("Medium"), "medium")

    def test_severity_low(self):
        self.assertEqual(map_severity_to_level("low"), "low")

    def test_severity_info_maps_to_low(self):
        self.assertEqual(map_severity_to_level("info"), "low")
        self.assertEqual(map_severity_to_level("INFO"), "low")

    def test_severity_unknown_maps_to_medium(self):
        self.assertEqual(map_severity_to_level("whatever"), "medium")

    def test_severity_non_string_maps_to_medium(self):
        self.assertEqual(map_severity_to_level(None), "medium")
        self.assertEqual(map_severity_to_level(99), "medium")


# ===========================================================================
# Task 4: Validate IP edge cases
# ===========================================================================

class TestValidateIP(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("8.8.8.8"))

    def test_valid_ipv4_cidr(self):
        self.assertTrue(validate_ip("10.0.0.0/8"))
        self.assertTrue(validate_ip("192.168.0.0/24"))
        self.assertTrue(validate_ip("0.0.0.0/0"))

    def test_valid_keywords(self):
        self.assertTrue(validate_ip("any"))
        self.assertTrue(validate_ip("ANY"))
        self.assertTrue(validate_ip("$EXTERNAL_NET"))
        self.assertTrue(validate_ip("$HOME_NET"))
        self.assertTrue(validate_ip("$external_net"))

    def test_empty_string_is_invalid(self):
        """Task 4: empty IP string must be rejected."""
        self.assertFalse(validate_ip(""))

    def test_none_is_invalid(self):
        """Task 4: None must not raise AttributeError - must return False."""
        self.assertFalse(validate_ip(None))

    def test_integer_is_invalid(self):
        self.assertFalse(validate_ip(12345))

    def test_octet_out_of_range(self):
        self.assertFalse(validate_ip("256.1.1.1"))
        self.assertFalse(validate_ip("192.168.1.256"))

    def test_random_string_is_invalid(self):
        self.assertFalse(validate_ip("not_an_ip"))
        self.assertFalse(validate_ip("abc.def.ghi.jkl"))


# ===========================================================================
# Task 4: Validate Port edge cases
# ===========================================================================

class TestValidatePort(unittest.TestCase):

    def test_port_zero_is_valid(self):
        """Task 4: port 0 is legal in Snort rules."""
        self.assertTrue(validate_port(0))
        self.assertTrue(validate_port("0"))

    def test_port_any_is_valid(self):
        self.assertTrue(validate_port("any"))
        self.assertTrue(validate_port("ANY"))

    def test_common_ports_valid(self):
        for port in (22, 80, 443, 8080, 65535):
            with self.subTest(port=port):
                self.assertTrue(validate_port(port))

    def test_string_numeric_port_valid(self):
        self.assertTrue(validate_port("443"))

    def test_port_minus_one_invalid(self):
        """Task 4: port -1 must be rejected."""
        self.assertFalse(validate_port(-1))
        self.assertFalse(validate_port("-1"))

    def test_port_65536_invalid(self):
        """Task 4: port 65536 exceeds the valid range."""
        self.assertFalse(validate_port(65536))

    def test_port_non_numeric_string_invalid(self):
        self.assertFalse(validate_port("http"))
        self.assertFalse(validate_port("abc"))


    def test_port_none_invalid(self):
        """validate_port(None) must reject None — either returns False or raises TypeError."""
        try:
            result = validate_port(None)
            self.assertFalse(result, "validate_port(None) should return False, got True")
        except TypeError:
            pass  # also acceptable: int(None) raises TypeError — None is clearly invalid



# ===========================================================================
# Task 2: Snort rule syntax validity
# ===========================================================================

class TestSnortRuleSyntax(unittest.TestCase):
    """Task 2 - Snort rule syntax validity."""

    # -- template structure --------------------------------------------------
    def test_template_contains_all_placeholders(self):
        for p in ["{protocol}", "{src_ip}", "{dst_port}", "{attack_desc}", "{technique_id}", "{sid}"]:
            with self.subTest(placeholder=p):
                self.assertIn(p, SNORT_RULE_TEMPLATE)

    def test_template_has_opening_parenthesis(self):
        self.assertIn("(", SNORT_RULE_TEMPLATE)

    def test_template_ends_with_closing_parenthesis(self):
        self.assertTrue(SNORT_RULE_TEMPLATE.strip().endswith(")"))

    # -- happy-path generation -----------------------------------------------
    def test_basic_tcp_rule_parses_correctly(self):
        rule = generate_snort_rule(
            src_ip="192.168.10.1", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110", sid=1000001,
        )
        parsed = parse_snort_rule(rule)
        self.assertEqual(parsed["action"], "alert")
        self.assertEqual(parsed["protocol"], "tcp")
        self.assertEqual(parsed["src_ip"], "192.168.10.1")
        self.assertEqual(parsed["dst_port"], "22")
        self.assertIn("SSH Brute Force", parsed["options"]["msg"])
        self.assertEqual(parsed["options"]["flow"], "to_server,established")
        self.assertEqual(parsed["options"]["threshold"], "type limit, track by_src, count 5, seconds 60")
        self.assertEqual(parsed["options"]["classtype"], "attempted-admin")
        self.assertEqual(parsed["options"]["reference"], "url,attack.mitre.org/techniques/T1110/")
        self.assertEqual(parsed["options"]["sid"], "1000001")
        self.assertEqual(parsed["options"]["rev"], "1")

    def test_udp_rule_is_syntactically_valid(self):
        rule = generate_snort_rule("any", "any", "udp", "DNS Flood", "T1498")
        self.assertEqual(parse_snort_rule(rule)["protocol"], "udp")

    def test_icmp_rule_is_syntactically_valid(self):
        rule = generate_snort_rule("any", "any", "icmp", "Ping Sweep", "T1018")
        self.assertEqual(parse_snort_rule(rule)["protocol"], "icmp")

    def test_ip_protocol_is_syntactically_valid(self):
        rule = generate_snort_rule("any", 80, "ip", "Generic IP", "T1040")
        self.assertEqual(parse_snort_rule(rule)["protocol"], "ip")

    # -- parentheses ---------------------------------------------------------
    def test_rule_has_opening_parenthesis(self):
        rule = generate_snort_rule("any", 80, "tcp", "Test", "T1234")
        self.assertIn("(", rule)

    def test_rule_ends_with_closing_parenthesis(self):
        rule = generate_snort_rule("any", 80, "tcp", "Test", "T1234")
        self.assertTrue(rule.strip().endswith(")"))

    # -- semicolons ----------------------------------------------------------
    def test_every_option_is_semicolon_terminated(self):
        """Task 2: the last option before ')' must be terminated by ';'"""
        rule = generate_snort_rule("any", 80, "tcp", "Test", "T1234")
        options_region = rule[rule.index("(") + 1 : -1].strip()
        self.assertTrue(
            options_region.endswith(";"),
            "Options block does not end with ';'. Got: ...%s" % options_region[-30:],
        )

    # -- SID -----------------------------------------------------------------
    def test_sid_is_present_and_positive(self):
        """Task 2: SID must appear in output and be a positive integer."""
        rule = generate_snort_rule("any", 80, "tcp", "Test", "T1234", sid=9999)
        parsed = parse_snort_rule(rule)
        self.assertEqual(int(parsed["options"]["sid"]), 9999)

    def test_sid_zero_raises(self):
        """Task 2: SID=0 must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 80, "tcp", "Test", "T1234", sid=0)

    def test_sid_negative_raises(self):
        """Task 2: Negative SID must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 80, "tcp", "Test", "T1234", sid=-5)

    # -- msg quoting ---------------------------------------------------------
    def test_msg_is_double_quoted(self):
        """Task 2: msg field must start and end with double quotes."""
        rule = generate_snort_rule("any", 80, "tcp", "Simple Test", "T1234")
        msg = parse_snort_rule(rule)["options"]["msg"]
        self.assertTrue(msg.startswith('"'), "msg does not start with double-quote")
        self.assertTrue(msg.endswith('"'), "msg does not end with double-quote")

    def test_semicolon_in_msg_is_escaped(self):
        """Task 2: semicolons inside msg must be escaped as \\;"""
        rule = generate_snort_rule("any", 80, "tcp", "End; payload", "T1190")
        self.assertIn("\\;", parse_snort_rule(rule)["options"]["msg"])

    def test_backslash_in_msg_is_escaped(self):
        """Task 2: backslashes inside msg must be doubled."""
        rule = generate_snort_rule("any", 80, "tcp", "Path\\to\\evil", "T1190")
        self.assertIn("\\\\", parse_snort_rule(rule)["options"]["msg"])

    def test_double_quotes_in_msg_are_escaped(self):
        """Task 2: literal double-quotes inside msg must be escaped."""
        rule = generate_snort_rule("any", 80, "tcp", 'Desc "quoted"', "T1190")
        self.assertIn('\\"', parse_snort_rule(rule)["options"]["msg"])

    # -- MITRE reference -----------------------------------------------------
    def test_reference_plain_technique(self):
        rule = generate_snort_rule("any", 80, "tcp", "SQLi", "T1190")
        ref = parse_snort_rule(rule)["options"]["reference"]
        self.assertEqual(ref, "url,attack.mitre.org/techniques/T1190/")

    def test_reference_sub_technique_dot_notation(self):
        rule = generate_snort_rule("any", 80, "tcp", "Brute", "T1110.001")
        ref = parse_snort_rule(rule)["options"]["reference"]
        self.assertEqual(ref, "url,attack.mitre.org/techniques/T1110/001/")

    def test_reference_full_mitre_url_input(self):
        rule = generate_snort_rule("any", 80, "tcp", "RCE", "https://attack.mitre.org/techniques/T1059/001/")
        ref = parse_snort_rule(rule)["options"]["reference"]
        self.assertEqual(ref, "url,attack.mitre.org/techniques/T1059/001/")

    # -- invalid input errors ------------------------------------------------
    def test_invalid_ip_raises(self):
        with self.assertRaises(ValueError):
            generate_snort_rule("256.0.0.1", 80, "tcp", "Desc", "T1234")

    def test_empty_ip_raises(self):
        """Task 4: empty string IP must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_snort_rule("", 80, "tcp", "Desc", "T1234")

    def test_none_ip_raises(self):
        """Task 4: None IP must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_snort_rule(None, 80, "tcp", "Desc", "T1234")

    def test_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 99999, "tcp", "Desc", "T1234")

    def test_negative_port_raises(self):
        """Task 4: port -1 must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_snort_rule("any", -1, "tcp", "Desc", "T1234")

    def test_unknown_protocol_ftp_raises(self):
        """Task 4: ftp is not a valid Snort protocol."""
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 80, "ftp", "Desc", "T1234")

    def test_unknown_protocol_http_raises(self):
        """Task 4: http is not a valid Snort protocol."""
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 80, "http", "Desc", "T1234")

    def test_unknown_protocol_ssh_raises(self):
        """Task 4: ssh is not a valid Snort protocol."""
        with self.assertRaises(ValueError):
            generate_snort_rule("any", 80, "ssh", "Desc", "T1234")

    def test_port_zero_generates_valid_rule(self):
        """Task 4: port 0 is valid and must produce a parseable Snort rule."""
        rule = generate_snort_rule("any", 0, "tcp", "Port0 test", "T1234")
        parsed = parse_snort_rule(rule)
        self.assertEqual(parsed["dst_port"], "0")

    def test_port_any_string_generates_valid_rule(self):
        rule = generate_snort_rule("any", "any", "tcp", "AnyPort test", "T1234")
        self.assertEqual(parse_snort_rule(rule)["dst_port"], "any")

    def test_cidr_source_ip_generates_valid_rule(self):
        rule = generate_snort_rule("10.0.0.0/8", 443, "tcp", "CIDR test", "T1234")
        self.assertEqual(parse_snort_rule(rule)["src_ip"], "10.0.0.0/8")


# ===========================================================================
# Task 5: SID auto-increment uniqueness
# ===========================================================================

class TestSIDAutoIncrement(unittest.TestCase):
    """Task 5 - SID auto-increment must not produce duplicates."""

    def _collect_auto_sids(self, count):
        sids = []
        for _ in range(count):
            rule = generate_snort_rule(
                src_ip="any", dst_port=80, protocol="tcp",
                attack_desc="auto SID test", technique_id="T1234", sid=None,
            )
            sids.append(int(parse_snort_rule(rule)["options"]["sid"]))
        return sids

    def test_sequential_sids_are_unique(self):
        """Task 5: 50 sequential auto-SID calls must all be unique."""
        sids = self._collect_auto_sids(50)
        self.assertEqual(len(sids), len(set(sids)),
                         "Duplicate SIDs found in sequential calls: %s" % sorted(sids))

    def test_sequential_sids_are_strictly_increasing(self):
        """Task 5: SIDs must be monotonically increasing."""
        sids = self._collect_auto_sids(20)
        for a, b in zip(sids, sids[1:]):
            self.assertLess(a, b, "SIDs not strictly increasing: %d >= %d" % (a, b))

    def test_explicit_sid_advances_counter(self):
        """Task 5: explicit SID ahead of the counter prevents future collision."""
        high_sid = 8_000_000
        generate_snort_rule("any", 80, "tcp", "explicit", "T1234", sid=high_sid)
        next_rule = generate_snort_rule("any", 80, "tcp", "next auto", "T1234", sid=None)
        next_sid = int(parse_snort_rule(next_rule)["options"]["sid"])
        self.assertEqual(next_sid, high_sid + 1,
                         "Expected %d, got %d" % (high_sid + 1, next_sid))

    def test_concurrent_sids_are_unique(self):
        """Task 5: SIDs generated from 20 concurrent threads must be unique."""
        results = []
        lock = threading.Lock()
        errors = []

        def worker():
            try:
                rule = generate_snort_rule("any", 80, "tcp", "thread test", "T1234", sid=None)
                sid = int(parse_snort_rule(rule)["options"]["sid"])
                with lock:
                    results.append(sid)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(errors, "Errors in threads: %s" % errors)
        self.assertEqual(len(results), len(set(results)),
                         "Duplicate SIDs in concurrent calls: %s" % sorted(results))

    def test_100_sequential_sids_no_duplicates(self):
        """Task 5: 100 sequential calls must produce 100 unique SIDs."""
        sids = self._collect_auto_sids(100)
        self.assertEqual(len(sids), len(set(sids)),
                         "Duplicate SIDs detected in 100 sequential auto-SID calls.")


# ===========================================================================
# Task 3: Sigma rule YAML parsing
# ===========================================================================

class TestSigmaRuleYAMLParsing(unittest.TestCase):
    """Task 3 - Sigma YAML parsing, schema validation, and semantics."""

    _LS  = {"category": "authentication", "product": "linux"}
    _DET = {"selection": {"EventID": 4625}, "condition": "selection"}

    def test_output_is_valid_yaml(self):
        """Task 3: generate_sigma_rule must produce valid YAML."""
        data = yaml.safe_load(generate_sigma_rule("SSH Brute Force", self._LS, self._DET, "HIGH"))
        self.assertIsInstance(data, dict)

    def test_required_schema_keys_present(self):
        """Task 3: All required Sigma schema keys must be present."""
        data = parse_sigma_yaml(generate_sigma_rule("SSH Brute Force", self._LS, self._DET, "HIGH"))
        for key in SIGMA_REQUIRED_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, data)

    def test_title_round_trips(self):
        title = "My Detection Rule"
        data = parse_sigma_yaml(generate_sigma_rule(title, self._LS, self._DET, "LOW"))
        self.assertEqual(data["title"], title)

    def test_status_is_lowercased(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "LOW", status="Experimental"))
        self.assertEqual(data["status"], "experimental")

    def test_logsource_round_trips(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "MEDIUM"))
        self.assertEqual(data["logsource"], self._LS)

    def test_detection_block_round_trips(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "HIGH"))
        self.assertEqual(data["detection"], self._DET)

    def test_severity_critical_maps_to_level_critical(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "CRITICAL"))
        self.assertEqual(data["level"], "critical")

    def test_severity_high_maps_to_level_high(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "HIGH"))
        self.assertEqual(data["level"], "high")

    def test_severity_medium_maps_to_level_medium(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "medium"))
        self.assertEqual(data["level"], "medium")

    def test_severity_low_maps_to_level_low(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "LOW"))
        self.assertEqual(data["level"], "low")

    def test_severity_info_maps_to_level_low(self):
        """Task 3: INFO severity must map to low level."""
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "INFO"))
        self.assertEqual(data["level"], "low")

    def test_severity_unknown_defaults_to_medium(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "superHigh"))
        self.assertEqual(data["level"], "medium")

    def test_technique_id_added_as_attack_tag(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "HIGH", technique_id="T1110.001"))
        self.assertIn("attack.t1110.001", data["tags"])

    def test_mitre_url_technique_id_normalised(self):
        data = parse_sigma_yaml(generate_sigma_rule(
            "T", self._LS, self._DET, "HIGH",
            technique_id="https://attack.mitre.org/techniques/T1190/",
        ))
        self.assertIn("attack.t1190", data["tags"])

    def test_plain_string_tags_lowercased(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "LOW", tags=["HoneyPot", "SSH"]))
        self.assertIn("honeypot", data["tags"])
        self.assertIn("ssh", data["tags"])

    def test_comma_separated_string_tags(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "LOW", tags="tag1, tag2,tag3"))
        for t in ("tag1", "tag2", "tag3"):
            self.assertIn(t, data["tags"])

    def test_mixed_tags_and_technique_id(self):
        data = parse_sigma_yaml(generate_sigma_rule(
            "T", self._LS, self._DET, "HIGH",
            tags=["honeypot", "T1110.001"],
            technique_id="https://attack.mitre.org/techniques/T1190/",
        ))
        self.assertIn("attack.t1190", data["tags"])
        self.assertIn("attack.t1110.001", data["tags"])
        self.assertIn("honeypot", data["tags"])

    def test_no_duplicate_tags(self):
        data = parse_sigma_yaml(generate_sigma_rule(
            "T", self._LS, self._DET, "HIGH",
            tags=["attack.t1190", "T1190"], technique_id="T1190",
        ))
        self.assertEqual(len(data["tags"]), len(set(data["tags"])),
                         "Duplicate tags found: %s" % data["tags"])

    def test_flat_detection_auto_wrapped_in_selection(self):
        flat = {"CommandLine|contains": "whoami", "User": "root"}
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, flat, "LOW"))
        self.assertIn("selection", data["detection"])
        self.assertEqual(data["detection"]["condition"], "selection")

    def test_structured_detection_missing_condition_gets_one(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, {"selection": {"EventID": 4625}}, "LOW"))
        self.assertEqual(data["detection"]["condition"], "selection")

    def test_multi_section_detection_gets_or_condition(self):
        multi = {"selection_a": {"CommandLine|contains": "whoami"}, "selection_b": {"User": "root"}}
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, multi, "LOW"))
        cond = data["detection"]["condition"]
        self.assertTrue(
            cond in ("selection_a or selection_b", "selection_b or selection_a"),
            "Unexpected condition: %s" % cond,
        )

    def test_detection_with_explicit_condition_preserved(self):
        det = {"selection": {"EventID": 1}, "condition": "selection"}
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, det, "LOW"))
        self.assertEqual(data["detection"]["condition"], "selection")

    # -- Task 4: invalid inputs raise ValueError ----------------------------
    def test_empty_title_raises(self):
        """Task 4: empty title must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_sigma_rule("", self._LS, self._DET, "LOW")

    def test_whitespace_title_raises(self):
        with self.assertRaises(ValueError):
            generate_sigma_rule("   ", self._LS, self._DET, "LOW")

    def test_none_title_raises(self):
        with self.assertRaises(ValueError):
            generate_sigma_rule(None, self._LS, self._DET, "LOW")

    def test_empty_logsource_raises(self):
        with self.assertRaises(ValueError):
            generate_sigma_rule("T", {}, self._DET, "LOW")

    def test_none_logsource_raises(self):
        with self.assertRaises(ValueError):
            generate_sigma_rule("T", None, self._DET, "LOW")

    def test_empty_detection_raises(self):
        with self.assertRaises(ValueError):
            generate_sigma_rule("T", self._LS, {}, "LOW")

    def test_empty_severity_raises(self):
        """Task 4: empty severity must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_sigma_rule("T", self._LS, self._DET, "")

    def test_empty_status_raises(self):
        with self.assertRaises(ValueError):
            generate_sigma_rule("T", self._LS, self._DET, "LOW", status="")

    def test_tags_none_produces_no_tags_key(self):
        data = parse_sigma_yaml(generate_sigma_rule("T", self._LS, self._DET, "LOW", tags=None))
        self.assertNotIn("tags", data)


# ===========================================================================
# Integration: generate_rules_for_campaign
# ===========================================================================

class TestGenerateRulesForCampaign(unittest.TestCase):
    """Integration tests for generate_rules_for_campaign."""

    def test_basic_single_technique(self):
        cluster = {
            "campaign_id": "alpha", "cluster_id": 1,
            "unique_sources": ["192.168.1.100"],
            "target_ports": [22], "protocols": ["tcp"],
        }
        mitre = {"technique_id": "T1110.001", "technique_name": "Brute Force", "severity": "HIGH"}
        result = generate_rules_for_campaign(cluster, mitre)
        meta = result["metadata"]
        self.assertEqual(meta["campaign_id"], "alpha")
        self.assertEqual(meta["cluster_id"], 1)
        self.assertEqual(meta["snort_rule_count"], 1)
        self.assertEqual(meta["sigma_rule_count"], 1)
        parsed = parse_snort_rule(result["snort_rules_list"][0])
        self.assertEqual(parsed["src_ip"], "192.168.1.100")
        self.assertEqual(parsed["dst_port"], "22")
        self.assertEqual(parsed["protocol"], "tcp")
        sigma = parse_sigma_yaml(result["sigma_rules_list"][0])
        self.assertEqual(sigma["level"], "high")

    def test_multiple_combinations_rule_count(self):
        """2 sources x 2 protocols x 2 ports x 2 techniques = 16 Snort rules."""
        cluster = {
            "campaign_id": "beta", "cluster_id": 2,
            "unique_sources": ["10.0.0.5", "10.0.0.6"],
            "target_ports": [80, 443], "protocols": ["tcp", "udp"],
        }
        mitre = [
            {"technique_id": "T1190", "technique_name": "Exploit App", "severity": "CRITICAL"},
            {"technique_id": "T1046", "technique_name": "Net Discovery",  "severity": "MEDIUM"},
        ]
        result = generate_rules_for_campaign(cluster, mitre)
        self.assertEqual(result["metadata"]["snort_rule_count"], 16)
        self.assertEqual(result["metadata"]["sigma_rule_count"], 2)
        for rule in result["snort_rules_list"]:
            parsed = parse_snort_rule(rule)
            self.assertIn(parsed["src_ip"], ["10.0.0.5", "10.0.0.6"])
            self.assertIn(parsed["protocol"], ["tcp", "udp"])
            self.assertIn(parsed["dst_port"], ["80", "443"])
        for ys in result["sigma_rules_list"]:
            sigma = parse_sigma_yaml(ys)
            self.assertIn(sigma["level"], ["critical", "medium"])

    def test_no_mitre_info_uses_fallback(self):
        result = generate_rules_for_campaign(
            {"unique_sources": ["192.168.1.1"], "target_ports": [80], "protocols": ["tcp"]}, None
        )
        self.assertEqual(result["metadata"]["sigma_rule_count"], 1)
        self.assertEqual(result["metadata"]["snort_rule_count"], 1)
        self.assertIn("T1046", result["metadata"]["techniques"])

    def test_unsupported_protocol_filtered_tcp_survives(self):
        """Task 4: unknown protocols are filtered; TCP falls through."""
        result = generate_rules_for_campaign(
            {"unique_sources": ["192.168.1.1"], "target_ports": [80], "protocols": ["http", "ssh", "tcp"]},
            None,
        )
        self.assertEqual(result["metadata"]["snort_rule_count"], 1)
        self.assertEqual(parse_snort_rule(result["snort_rules_list"][0])["protocol"], "tcp")

    def test_invalid_ip_filtered_out(self):
        """Task 4: invalid IPs are silently dropped; valid ones remain."""
        result = generate_rules_for_campaign(
            {"unique_sources": ["not-an-ip", "1.1.1.1"], "target_ports": [8080], "protocols": ["tcp"]},
            None,
        )
        self.assertEqual(result["metadata"]["snort_rule_count"], 1)
        self.assertEqual(parse_snort_rule(result["snort_rules_list"][0])["src_ip"], "1.1.1.1")

    def test_invalid_port_filtered_out(self):
        """Task 4: out-of-range ports are dropped; valid ones remain."""
        result = generate_rules_for_campaign(
            {"unique_sources": ["1.1.1.1"], "target_ports": [99999, 8080], "protocols": ["tcp"]},
            None,
        )
        self.assertEqual(result["metadata"]["snort_rule_count"], 1)
        self.assertEqual(parse_snort_rule(result["snort_rules_list"][0])["dst_port"], "8080")

    def test_all_invalid_sources_fallback_to_any(self):
        result = generate_rules_for_campaign(
            {"unique_sources": ["not-ip", "also-bad"], "target_ports": [80], "protocols": ["tcp"]},
            None,
        )
        self.assertEqual(parse_snort_rule(result["snort_rules_list"][0])["src_ip"], "any")

    def test_all_unsupported_protocols_fallback_to_ip(self):
        result = generate_rules_for_campaign(
            {"unique_sources": ["1.1.1.1"], "target_ports": [80], "protocols": ["ftp", "ssh"]},
            None,
        )
        self.assertEqual(parse_snort_rule(result["snort_rules_list"][0])["protocol"], "ip")

    def test_empty_cluster_data_does_not_crash(self):
        result = generate_rules_for_campaign({}, None)
        for key in ("snort_rules", "sigma_rules", "snort_rules_list", "sigma_rules_list", "metadata"):
            self.assertIn(key, result)

    def test_all_snort_rules_are_syntactically_valid(self):
        cluster = {
            "campaign_id": "gamma",
            "unique_sources": ["10.10.10.10"],
            "target_ports": [443, 8443], "protocols": ["tcp"],
        }
        mitre = [
            {"technique_id": "T1059", "technique_name": "Cmd Exec", "severity": "HIGH"},
            {"technique_id": "T1071", "technique_name": "App Protocol", "severity": "MEDIUM"},
        ]
        for rule_str in generate_rules_for_campaign(cluster, mitre)["snort_rules_list"]:
            with self.subTest(rule=rule_str[:60]):
                parse_snort_rule(rule_str)  # must not raise

    def test_all_sigma_rules_are_valid_yaml(self):
        cluster = {
            "campaign_id": "delta",
            "unique_sources": ["10.10.10.10"],
            "target_ports": [80], "protocols": ["tcp"],
        }
        mitre = [
            {"technique_id": "T1059", "technique_name": "Cmd", "severity": "HIGH"},
            {"technique_id": "T1071", "technique_name": "Proto", "severity": "MEDIUM"},
        ]
        for ys in generate_rules_for_campaign(cluster, mitre)["sigma_rules_list"]:
            with self.subTest(yaml_start=ys[:60]):
                parse_sigma_yaml(ys)  # must not raise

    def test_snort_rules_string_contains_all_individual_rules(self):
        cluster = {
            "campaign_id": "epsilon",
            "unique_sources": ["1.2.3.4"],
            "target_ports": [22, 23], "protocols": ["tcp"],
        }
        result = generate_rules_for_campaign(cluster, None)
        joined = result["snort_rules"]
        for rule in result["snort_rules_list"]:
            self.assertIn(rule, joined)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
