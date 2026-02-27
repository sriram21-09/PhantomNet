import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.response_executor import ResponseExecutor

class TestResponseExecutor(unittest.TestCase):
    def setUp(self):
        # Create a fresh executor for each test
        self.executor = ResponseExecutor()

    @patch('services.response_executor.subprocess.run')
    def test_a_block_ip_linux(self, mock_run):
        """Test that iptables is called on Linux."""
        self.executor.system = 'Linux'
        self.executor._block_ip("1.2.3.4")
        
        args = mock_run.call_args[0][0]
        self.assertIn("iptables", args, f"Expected 'iptables' in {args}")
        self.assertIn("1.2.3.4", args)

    @patch('services.response_executor.subprocess.run')
    def test_b_block_ip_windows(self, mock_run):
        """Test that netsh is called on Windows."""
        self.executor.system = 'Windows'
        self.executor._block_ip("8.8.8.8")
        
        args = mock_run.call_args[0][0]
        self.assertIn("netsh", args, f"Expected 'netsh' in {args}")
        self.assertIn("remoteip=8.8.8.8", args)

    @patch('services.response_executor.subprocess.run')
    def test_c_scale_honeypots(self, mock_run):
        """Test that docker-compose scale is called."""
        self.executor._scale_honeypots("SSH_ATTACK")
        
        args = mock_run.call_args[0][0]
        self.assertIn("docker-compose", args)
        self.assertIn("--scale", args)
        self.assertIn("ssh_honeypot=2", args)

    @patch('services.response_executor.ResponseExecutor._block_ip')
    @patch('services.response_executor.ResponseExecutor._scale_honeypots')
    def test_d_execute_response_matrix(self, mock_scale, mock_block):
        """Test the response matrix triggers correct actions."""
        # Test HIGH level
        self.executor.execute_response("HIGH", source_ip="1.1.1.1")
        mock_block.assert_called_with("1.1.1.1")
        
        # Test CRITICAL level
        self.executor.execute_response("CRITICAL", source_ip="2.2.2.2", attack_type="HTTP")
        mock_block.assert_any_call("2.2.2.2")
        mock_scale.assert_called()

if __name__ == "__main__":
    unittest.main()
