import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.response_executor import ResponseExecutor


class TestResponseExecutor(unittest.TestCase):
    def setUp(self):
        # Create a fresh executor for each test
        self.executor = ResponseExecutor()

    @patch("services.response_executor.platform.system", return_value="Linux")
    @patch("services.response_executor.subprocess.run")
    def test_a_block_ip_linux(self, mock_run, mock_system):
        """Test that iptables is called on Linux."""
        self.executor._action_block_ip("1.2.3.4", 30, "HIGH")

        args = mock_run.call_args[0][0]
        self.assertIn("iptables", args, f"Expected 'iptables' in {args}")
        self.assertIn("1.2.3.4", args)

    @patch("services.response_executor.platform.system", return_value="Windows")
    @patch("services.response_executor.subprocess.run")
    def test_b_block_ip_windows(self, mock_run, mock_system):
        """Test that netsh is called on Windows."""
        self.executor._action_block_ip("8.8.8.8", 30, "HIGH")

        args = mock_run.call_args[0][0]
        self.assertIn("netsh", args, f"Expected 'netsh' in {args}")
        self.assertIn("remoteip=8.8.8.8", args)

    def test_c_scale_honeypots(self):
        """Test that honeypot scaling returns correct configuration."""
        res = self.executor._action_scale_honeypots("HIGH", "SSH")
        self.assertEqual(res["status"], "scaling_requested")
        self.assertEqual(res["protocol"], "SSH")

    @patch("services.response_executor.ResponseExecutor._action_block_ip")
    @patch("services.response_executor.ResponseExecutor._action_scale_honeypots")
    def test_d_execute_response_matrix(self, mock_scale, mock_block):
        """Test the response matrix triggers correct actions."""
        # Test HIGH level
        self.executor.execute("1.1.1.1", 85.0, "HIGH")
        mock_block.assert_called_with("1.1.1.1", 30, "HIGH")

        # Test CRITICAL level
        self.executor.execute("2.2.2.2", 95.0, "CRITICAL", protocol="HTTP")
        mock_block.assert_any_call("2.2.2.2", 0, "CRITICAL")
        mock_scale.assert_called_with("CRITICAL", "HTTP")


if __name__ == "__main__":
    unittest.main()
