#!/usr/bin/env python3
"""
Test suite for NessusExecutor class

This module contains unit tests for the Nessus scanning functionality.
"""

import unittest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
import sys
import time

# Add the parent directory to the path to import attack_executor
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from attack_executor.scan.nessus import NessusExecutor


class TestNessusExecutor(unittest.TestCase):
    """Test cases for NessusExecutor class"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.nessus = NessusExecutor()
        self.test_target = "192.168.1.100"
        
        # Sample JSON results for testing
        self.sample_json_results = json.dumps({
            "info": {
                "name": "Test Scan",
                "scan_start": "2024-01-01T10:00:00Z",
                "scan_end": "2024-01-01T11:00:00Z",
                "targets": "192.168.1.100"
            },
            "hosts": [
                {
                    "hostname": "192.168.1.100",
                    "operating_system": "Linux Kernel 5.4",
                    "vulnerabilities": [
                        {
                            "plugin_id": "12345",
                            "plugin_name": "SSH Weak Encryption",
                            "severity": 3,
                            "description": "Weak encryption detected"
                        },
                        {
                            "plugin_id": "67890",
                            "plugin_name": "HTTP Information Disclosure",
                            "severity": 2,
                            "description": "Information disclosure detected"
                        }
                    ]
                }
            ]
        })

    def test_init(self):
        """Test NessusExecutor initialization"""
        # Test default initialization
        nessus = NessusExecutor()
        self.assertEqual(nessus.nessus_path, "nessuscli")
        self.assertIsNone(nessus.last_scan_id)
        self.assertIsNone(nessus.last_scan_results)
        
        # Test custom path initialization
        custom_path = "/custom/path/nessuscli"
        nessus_custom = NessusExecutor(nessus_path=custom_path)
        self.assertEqual(nessus_custom.nessus_path, custom_path)

    @patch('subprocess.run')
    def test_check_nessus_installation(self, mock_run):
        """Test Nessus installation check"""
        # Test successful installation check
        mock_run.return_value.returncode = 0
        result = self.nessus._check_nessus_installation()
        self.assertTrue(result)
        
        # Test failed installation check
        mock_run.return_value.returncode = 1
        result = self.nessus._check_nessus_installation()
        self.assertFalse(result)
        
        # Test FileNotFoundError
        mock_run.side_effect = FileNotFoundError()
        result = self.nessus._check_nessus_installation()
        self.assertFalse(result)

    @patch('subprocess.run')
    def test_run_nessus_command(self, mock_run):
        """Test running Nessus commands"""
        # Test successful command
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "success"
        mock_run.return_value.stderr = ""
        
        result = self.nessus._run_nessus_command(["test", "args"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "success")
        
        # Test failed command
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "error message"
        
        result = self.nessus._run_nessus_command(["test", "args"])
        self.assertEqual(result.returncode, 1)

    @patch.object(NessusExecutor, '_run_nessus_command')
    def test_list_policies(self, mock_run_command):
        """Test listing scan policies"""
        # Test successful policy listing
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "ID\tName\tDescription\n123\tBasic Scan\tBasic network scan\n456\tWeb Scan\tWeb application scan"
        mock_run_command.return_value = mock_result
        
        policies = self.nessus.list_policies()
        self.assertEqual(len(policies), 2)
        self.assertEqual(policies[0]['id'], '123')
        self.assertEqual(policies[0]['name'], 'Basic Scan')
        self.assertEqual(policies[1]['id'], '456')
        self.assertEqual(policies[1]['name'], 'Web Scan')
        
        # Test failed policy listing
        mock_result.returncode = 1
        mock_result.stderr = "error"
        mock_run_command.return_value = mock_result
        
        policies = self.nessus.list_policies()
        self.assertEqual(len(policies), 0)

    @patch.object(NessusExecutor, '_run_nessus_command')
    def test_create_basic_scan_policy(self, mock_run_command):
        """Test creating a basic scan policy"""
        # Test successful policy creation
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run_command.return_value = mock_result
        
        result = self.nessus.create_basic_scan_policy("Test Policy")
        self.assertTrue(result)
        
        # Test failed policy creation
        mock_result.returncode = 1
        mock_result.stderr = "error"
        mock_run_command.return_value = mock_result
        
        result = self.nessus.create_basic_scan_policy("Test Policy")
        self.assertFalse(result)

    @patch.object(NessusExecutor, '_run_nessus_command')
    def test_scan_target(self, mock_run_command):
        """Test scanning a target"""
        # Test successful scan launch
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Scan launched with ID: scan123"
        mock_run_command.return_value = mock_result
        
        scan_id = self.nessus.scan_target(self.test_target)
        self.assertEqual(scan_id, "scan123")
        self.assertEqual(self.nessus.last_scan_id, "scan123")
        
        # Test failed scan launch
        mock_result.returncode = 1
        mock_result.stderr = "error"
        mock_run_command.return_value = mock_result
        
        scan_id = self.nessus.scan_target(self.test_target)
        self.assertIsNone(scan_id)

    @patch.object(NessusExecutor, '_run_nessus_command')
    def test_get_scan_status(self, mock_run_command):
        """Test getting scan status"""
        # Set up a scan ID
        self.nessus.last_scan_id = "scan123"
        
        # Test successful status check
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "running"
        mock_run_command.return_value = mock_result
        
        status = self.nessus.get_scan_status()
        self.assertEqual(status, "running")
        
        # Test completed status
        mock_result.stdout = "completed"
        mock_run_command.return_value = mock_result
        
        status = self.nessus.get_scan_status()
        self.assertEqual(status, "completed")
        
        # Test no scan ID
        self.nessus.last_scan_id = None
        status = self.nessus.get_scan_status()
        self.assertIsNone(status)

    @patch.object(NessusExecutor, 'get_scan_status')
    @patch('time.sleep')
    def test_wait_for_scan_completion(self, mock_sleep, mock_get_status):
        """Test waiting for scan completion"""
        self.nessus.last_scan_id = "scan123"
        
        # Test successful completion
        mock_get_status.side_effect = ["running", "running", "completed"]
        
        result = self.nessus.wait_for_scan_completion(check_interval=1, max_wait=10)
        self.assertTrue(result)
        
        # Test failed scan
        mock_get_status.side_effect = ["running", "failed"]
        
        result = self.nessus.wait_for_scan_completion(check_interval=1, max_wait=10)
        self.assertFalse(result)
        
        # Test timeout (mock time.time to simulate timeout)
        with patch('time.time') as mock_time:
            mock_time.side_effect = [0, 5, 15]  # Simulate time progression
            mock_get_status.return_value = "running"
            
            result = self.nessus.wait_for_scan_completion(check_interval=1, max_wait=10)
            self.assertFalse(result)

    @patch.object(NessusExecutor, '_run_nessus_command')
    def test_get_scan_results(self, mock_run_command):
        """Test getting scan results"""
        self.nessus.last_scan_id = "scan123"
        
        # Test successful results retrieval
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = self.sample_json_results
        mock_run_command.return_value = mock_result
        
        results = self.nessus.get_scan_results()
        self.assertEqual(results, self.sample_json_results)
        self.assertEqual(self.nessus.last_scan_results, self.sample_json_results)
        
        # Test failed results retrieval
        mock_result.returncode = 1
        mock_result.stderr = "error"
        mock_run_command.return_value = mock_result
        
        results = self.nessus.get_scan_results()
        self.assertIsNone(results)

    def test_parse_json_results(self):
        """Test parsing JSON scan results"""
        # Test successful parsing
        parsed = self.nessus.parse_json_results(self.sample_json_results)
        
        self.assertEqual(parsed['scan_info']['name'], "Test Scan")
        self.assertEqual(parsed['host_count'], 1)
        self.assertEqual(parsed['vulnerability_count'], 2)
        self.assertEqual(len(parsed['hosts']), 1)
        self.assertEqual(len(parsed['vulnerabilities']), 2)
        
        # Check host information
        host = parsed['hosts'][0]
        self.assertEqual(host['ip'], "192.168.1.100")
        self.assertEqual(host['high_vulns'], 1)
        self.assertEqual(host['medium_vulns'], 1)
        
        # Check vulnerability information
        vuln = parsed['vulnerabilities'][0]
        self.assertEqual(vuln['plugin_id'], "12345")
        self.assertEqual(vuln['severity'], 3)
        
        # Test parsing invalid JSON
        parsed = self.nessus.parse_json_results("invalid json")
        self.assertEqual(parsed, {})
        
        # Test parsing with no results
        parsed = self.nessus.parse_json_results()
        self.assertEqual(parsed, {})

    def test_generate_summary_report(self):
        """Test generating summary reports"""
        # Parse sample results first
        parsed_results = self.nessus.parse_json_results(self.sample_json_results)
        
        # Generate report
        report = self.nessus.generate_summary_report(parsed_results)
        
        # Check report content
        self.assertIn("NESSUS VULNERABILITY SCAN REPORT", report)
        self.assertIn("Test Scan", report)
        self.assertIn("192.168.1.100", report)
        self.assertIn("Total Vulnerabilities: 2", report)
        self.assertIn("SSH Weak Encryption", report)
        
        # Test with no results
        report = self.nessus.generate_summary_report({})
        self.assertIn("No scan results available", report)

    def test_save_results_to_file(self):
        """Test saving results to file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        try:
            # Test successful file save
            content = "test content"
            result = self.nessus.save_results_to_file(temp_filename, content)
            self.assertTrue(result)
            
            # Verify file content
            with open(temp_filename, 'r') as f:
                saved_content = f.read()
            self.assertEqual(saved_content, content)
            
        finally:
            # Clean up
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
        
        # Test failed file save (invalid path)
        result = self.nessus.save_results_to_file("/invalid/path/file.txt", "content")
        self.assertFalse(result)

    @patch.object(NessusExecutor, 'scan_target')
    @patch.object(NessusExecutor, 'wait_for_scan_completion')
    @patch.object(NessusExecutor, 'get_scan_results')
    @patch.object(NessusExecutor, 'parse_json_results')
    @patch.object(NessusExecutor, 'generate_summary_report')
    def test_quick_scan(self, mock_report, mock_parse, mock_results, 
                       mock_wait, mock_scan):
        """Test quick scan functionality"""
        # Set up mocks for successful scan
        mock_scan.return_value = "scan123"
        mock_wait.return_value = True
        mock_results.return_value = self.sample_json_results
        mock_parse.return_value = {"vulnerability_count": 2}
        mock_report.return_value = "Test report"
        
        # Test successful quick scan
        results = self.nessus.quick_scan(self.test_target)
        self.assertIsNotNone(results)
        self.assertEqual(results["vulnerability_count"], 2)
        
        # Test failed scan launch
        mock_scan.return_value = None
        results = self.nessus.quick_scan(self.test_target)
        self.assertIsNone(results)
        
        # Test without waiting for completion
        mock_scan.return_value = "scan123"
        results = self.nessus.quick_scan(self.test_target, wait_for_completion=False)
        self.assertIsNone(results)

    def test_vulnerability_severity_mapping(self):
        """Test vulnerability severity mapping"""
        # Create test data with different severities
        test_data = json.dumps({
            "info": {"name": "Test", "targets": "test"},
            "hosts": [{
                "hostname": "test",
                "vulnerabilities": [
                    {"severity": 4, "plugin_id": "1", "plugin_name": "Critical"},
                    {"severity": 3, "plugin_id": "2", "plugin_name": "High"},
                    {"severity": 2, "plugin_id": "3", "plugin_name": "Medium"},
                    {"severity": 1, "plugin_id": "4", "plugin_name": "Low"},
                    {"severity": 0, "plugin_id": "5", "plugin_name": "Info"}
                ]
            }]
        })
        
        parsed = self.nessus.parse_json_results(test_data)
        host = parsed['hosts'][0]
        
        self.assertEqual(host['critical_vulns'], 1)
        self.assertEqual(host['high_vulns'], 1)
        self.assertEqual(host['medium_vulns'], 1)
        self.assertEqual(host['low_vulns'], 1)
        self.assertEqual(host['info_vulns'], 1)

    def test_edge_cases(self):
        """Test edge cases and error conditions"""
        # Test with empty scan results
        empty_data = json.dumps({"info": {}, "hosts": []})
        parsed = self.nessus.parse_json_results(empty_data)
        self.assertEqual(parsed['host_count'], 0)
        self.assertEqual(parsed['vulnerability_count'], 0)
        
        # Test with malformed data
        malformed_data = json.dumps({"unexpected": "structure"})
        parsed = self.nessus.parse_json_results(malformed_data)
        self.assertEqual(parsed['host_count'], 0)
        
        # Test report generation with empty data
        report = self.nessus.generate_summary_report(parsed)
        self.assertIn("Total Hosts Scanned: 0", report)


class TestNessusIntegration(unittest.TestCase):
    """Integration tests for NessusExecutor (require actual Nessus installation)"""
    
    def setUp(self):
        """Set up integration test fixtures"""
        self.nessus = NessusExecutor()
        # Skip integration tests if Nessus is not available
        if not self.nessus._check_nessus_installation():
            self.skipTest("Nessus CLI not available for integration tests")

    def test_nessus_installation_check(self):
        """Test that Nessus is properly installed and accessible"""
        self.assertTrue(self.nessus._check_nessus_installation())

    @unittest.skip("Requires actual Nessus setup and target")
    def test_real_scan_workflow(self):
        """Test actual scan workflow (disabled by default)"""
        # This test is skipped by default as it requires:
        # 1. Nessus to be properly installed and configured
        # 2. Valid scan targets
        # 3. Appropriate permissions
        
        target = "127.0.0.1"  # Localhost for testing
        
        # Launch scan
        scan_id = self.nessus.scan_target(target)
        self.assertIsNotNone(scan_id)
        
        # Check status
        status = self.nessus.get_scan_status(scan_id)
        self.assertIsNotNone(status)
        
        # Note: In a real test, you might wait for completion
        # but that could take a very long time


def run_tests():
    """Run all tests"""
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(unittest.makeSuite(TestNessusExecutor))
    suite.addTest(unittest.makeSuite(TestNessusIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    # Run tests when script is executed directly
    success = run_tests()
    sys.exit(0 if success else 1) 