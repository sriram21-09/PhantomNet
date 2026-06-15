import unittest

from sentinel.rule_generator import (
    generate_snort_rule, 
    validate_ip, 
    validate_port,
    SNORT_RULE_TEMPLATE
)

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
        self.assertIn("alert tcp $EXTERNAL_NET any -> $HOME_NET 22", rule)
        self.assertIn('msg:"SSH Brute Force"', rule)
        self.assertIn("flow:to_server,established", rule)
        self.assertIn("threshold:type limit, track by_src, count 5, seconds 60", rule)
        self.assertIn("classtype:attempted-admin", rule)
        self.assertIn("reference:url,attack.mitre.org/techniques/T1110", rule)
        self.assertIn("sid:1000001", rule)
        self.assertIn("rev:1", rule)

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

if __name__ == '__main__':
    unittest.main()
