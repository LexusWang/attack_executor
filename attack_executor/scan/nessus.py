import subprocess
import sys
import json
import time
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Union


class NessusExecutor:
    """
    A comprehensive Nessus scanner executor that provides methods for:
    - Managing Nessus policies and templates
    - Running vulnerability scans on target IP addresses
    - Retrieving and parsing scan results
    - Generating reports in various formats
    """
    
    def __init__(self, nessus_path: str = "nessuscli"):
        """
        Initialize the Nessus executor.
        
        Args:
            nessus_path: Path to the Nessus CLI executable (default: "nessuscli")
        """
        self.nessus_path = nessus_path
        self.last_scan_id = None
        self.last_scan_results = None
        
        # Check if Nessus CLI is available
        if not self._check_nessus_installation():
            print("[!] Warning: Nessus CLI not found. Some features may not work.")
    
    def _check_nessus_installation(self) -> bool:
        """Check if Nessus CLI is installed and accessible."""
        try:
            result = subprocess.run([self.nessus_path, "--help"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _run_nessus_command(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Run a Nessus CLI command with error handling.
        
        Args:
            args: Command arguments
            timeout: Command timeout in seconds
            
        Returns:
            subprocess.CompletedProcess object
        """
        cmd = [self.nessus_path] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                print(f"[!] Nessus command failed: {result.stderr.strip()}", file=sys.stderr)
            return result
        except subprocess.TimeoutExpired:
            print(f"[!] Nessus command timed out after {timeout} seconds", file=sys.stderr)
            raise
        except Exception as e:
            print(f"[!] Error running Nessus command: {e}", file=sys.stderr)
            raise
    
    def list_policies(self) -> List[Dict]:
        """
        List all available Nessus scan policies.
        
        Returns:
            List of policy dictionaries with id, name, and description
        """
        try:
            result = self._run_nessus_command(["policy", "list"])
            if result.returncode == 0:
                # Parse the output to extract policy information
                policies = []
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            policies.append({
                                'id': parts[0].strip(),
                                'name': parts[1].strip(),
                                'description': parts[2].strip() if len(parts) > 2 else ''
                            })
                return policies
            else:
                print(f"[!] Failed to list policies: {result.stderr}")
                return []
        except Exception as e:
            print(f"[!] Error listing policies: {e}")
            return []
    
    def create_basic_scan_policy(self, policy_name: str = "Basic Network Scan") -> bool:
        """
        Create a basic network scan policy.
        
        Args:
            policy_name: Name for the new policy
            
        Returns:
            True if policy created successfully, False otherwise
        """
        try:
            # Create a basic policy configuration
            result = self._run_nessus_command([
                "policy", "add", 
                "--name", policy_name,
                "--template", "basic"
            ])
            
            if result.returncode == 0:
                print(f"[+] Successfully created policy: {policy_name}")
                return True
            else:
                print(f"[!] Failed to create policy: {result.stderr}")
                return False
        except Exception as e:
            print(f"[!] Error creating policy: {e}")
            return False
    
    def scan_target(self, target: str, policy_name: str = "Basic Network Scan", 
                   scan_name: Optional[str] = None) -> Optional[str]:
        """
        Launch a vulnerability scan against a target IP address.
        
        Args:
            target: Target IP address or hostname
            policy_name: Name of the scan policy to use
            scan_name: Optional custom name for the scan
            
        Returns:
            Scan ID if successful, None otherwise
        """
        if not scan_name:
            scan_name = f"Scan_{target}_{int(time.time())}"
        
        try:
            result = self._run_nessus_command([
                "scan", "new",
                "--name", scan_name,
                "--targets", target,
                "--policy", policy_name
            ])
            
            if result.returncode == 0:
                # Extract scan ID from output
                scan_id = result.stdout.strip().split()[-1]
                self.last_scan_id = scan_id
                print(f"[+] Scan launched successfully. Scan ID: {scan_id}")
                return scan_id
            else:
                print(f"[!] Failed to launch scan: {result.stderr}")
                return None
        except Exception as e:
            print(f"[!] Error launching scan: {e}")
            return None
    
    def get_scan_status(self, scan_id: Optional[str] = None) -> Optional[str]:
        """
        Get the status of a scan.
        
        Args:
            scan_id: Scan ID (uses last scan if not provided)
            
        Returns:
            Scan status string or None if error
        """
        if not scan_id:
            scan_id = self.last_scan_id
        
        if not scan_id:
            print("[!] No scan ID provided or available")
            return None
        
        try:
            result = self._run_nessus_command(["scan", "status", scan_id])
            if result.returncode == 0:
                status = result.stdout.strip()
                print(f"[*] Scan {scan_id} status: {status}")
                return status
            else:
                print(f"[!] Failed to get scan status: {result.stderr}")
                return None
        except Exception as e:
            print(f"[!] Error getting scan status: {e}")
            return None
    
    def wait_for_scan_completion(self, scan_id: Optional[str] = None, 
                               check_interval: int = 30, max_wait: int = 3600) -> bool:
        """
        Wait for a scan to complete.
        
        Args:
            scan_id: Scan ID (uses last scan if not provided)
            check_interval: How often to check status (seconds)
            max_wait: Maximum time to wait (seconds)
            
        Returns:
            True if scan completed, False if timeout or error
        """
        if not scan_id:
            scan_id = self.last_scan_id
        
        if not scan_id:
            print("[!] No scan ID provided or available")
            return False
        
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            status = self.get_scan_status(scan_id)
            
            if status and "completed" in status.lower():
                print(f"[+] Scan {scan_id} completed successfully")
                return True
            elif status and "failed" in status.lower():
                print(f"[!] Scan {scan_id} failed")
                return False
            
            print(f"[*] Waiting for scan completion... ({int(time.time() - start_time)}s elapsed)")
            time.sleep(check_interval)
        
        print(f"[!] Scan did not complete within {max_wait} seconds")
        return False
    
    def get_scan_results(self, scan_id: Optional[str] = None, 
                        format_type: str = "json") -> Optional[str]:
        """
        Retrieve scan results.
        
        Args:
            scan_id: Scan ID (uses last scan if not provided)
            format_type: Output format ("json", "xml", "csv")
            
        Returns:
            Scan results as string or None if error
        """
        if not scan_id:
            scan_id = self.last_scan_id
        
        if not scan_id:
            print("[!] No scan ID provided or available")
            return None
        
        try:
            result = self._run_nessus_command([
                "scan", "export", scan_id,
                "--format", format_type
            ])
            
            if result.returncode == 0:
                self.last_scan_results = result.stdout
                print(f"[+] Successfully retrieved scan results in {format_type} format")
                return result.stdout
            else:
                print(f"[!] Failed to get scan results: {result.stderr}")
                return None
        except Exception as e:
            print(f"[!] Error getting scan results: {e}")
            return None
    
    def parse_json_results(self, json_results: Optional[str] = None) -> Dict:
        """
        Parse JSON scan results into a structured format.
        
        Args:
            json_results: JSON results string (uses last results if not provided)
            
        Returns:
            Parsed results dictionary
        """
        if not json_results:
            json_results = self.last_scan_results
        
        if not json_results:
            print("[!] No scan results available")
            return {}
        
        try:
            data = json.loads(json_results)
            
            # Extract key information
            summary = {
                'scan_info': {
                    'name': data.get('info', {}).get('name', 'Unknown'),
                    'start_time': data.get('info', {}).get('scan_start', ''),
                    'end_time': data.get('info', {}).get('scan_end', ''),
                    'target': data.get('info', {}).get('targets', ''),
                },
                'host_count': len(data.get('hosts', [])),
                'vulnerability_count': 0,
                'hosts': [],
                'vulnerabilities': []
            }
            
            # Process each host
            for host in data.get('hosts', []):
                host_info = {
                    'ip': host.get('hostname', ''),
                    'os': host.get('operating_system', ''),
                    'critical_vulns': 0,
                    'high_vulns': 0,
                    'medium_vulns': 0,
                    'low_vulns': 0,
                    'info_vulns': 0
                }
                
                # Count vulnerabilities by severity
                for vuln in host.get('vulnerabilities', []):
                    severity = vuln.get('severity', 0)
                    if severity == 4:
                        host_info['critical_vulns'] += 1
                    elif severity == 3:
                        host_info['high_vulns'] += 1
                    elif severity == 2:
                        host_info['medium_vulns'] += 1
                    elif severity == 1:
                        host_info['low_vulns'] += 1
                    else:
                        host_info['info_vulns'] += 1
                    
                    summary['vulnerability_count'] += 1
                    
                    # Add to vulnerability list
                    summary['vulnerabilities'].append({
                        'host': host_info['ip'],
                        'plugin_id': vuln.get('plugin_id', ''),
                        'plugin_name': vuln.get('plugin_name', ''),
                        'severity': severity,
                        'description': vuln.get('description', '')
                    })
                
                summary['hosts'].append(host_info)
            
            return summary
            
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing JSON results: {e}")
            return {}
        except Exception as e:
            print(f"[!] Error processing scan results: {e}")
            return {}
    
    def generate_summary_report(self, scan_results: Optional[Dict] = None) -> str:
        """
        Generate a human-readable summary report.
        
        Args:
            scan_results: Parsed scan results (uses last parsed results if not provided)
            
        Returns:
            Formatted summary report string
        """
        if not scan_results and self.last_scan_results:
            scan_results = self.parse_json_results()
        
        if not scan_results:
            return "No scan results available for report generation."
        
        report = []
        report.append("=" * 60)
        report.append("NESSUS VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        report.append("")
        
        # Scan information
        scan_info = scan_results.get('scan_info', {})
        report.append(f"Scan Name: {scan_info.get('name', 'Unknown')}")
        report.append(f"Target: {scan_info.get('target', 'Unknown')}")
        report.append(f"Start Time: {scan_info.get('start_time', 'Unknown')}")
        report.append(f"End Time: {scan_info.get('end_time', 'Unknown')}")
        report.append("")
        
        # Summary statistics
        report.append("SCAN SUMMARY")
        report.append("-" * 20)
        report.append(f"Total Hosts Scanned: {scan_results.get('host_count', 0)}")
        report.append(f"Total Vulnerabilities: {scan_results.get('vulnerability_count', 0)}")
        report.append("")
        
        # Host details
        report.append("HOST DETAILS")
        report.append("-" * 20)
        for host in scan_results.get('hosts', []):
            report.append(f"Host: {host.get('ip', 'Unknown')}")
            report.append(f"  OS: {host.get('os', 'Unknown')}")
            report.append(f"  Critical: {host.get('critical_vulns', 0)}")
            report.append(f"  High: {host.get('high_vulns', 0)}")
            report.append(f"  Medium: {host.get('medium_vulns', 0)}")
            report.append(f"  Low: {host.get('low_vulns', 0)}")
            report.append(f"  Info: {host.get('info_vulns', 0)}")
            report.append("")
        
        # Top vulnerabilities
        vulnerabilities = scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            report.append("TOP VULNERABILITIES (by severity)")
            report.append("-" * 40)
            # Sort by severity (descending)
            sorted_vulns = sorted(vulnerabilities, key=lambda x: x.get('severity', 0), reverse=True)
            
            for vuln in sorted_vulns[:10]:  # Show top 10
                severity_names = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
                severity = severity_names.get(vuln.get('severity', 0), "UNKNOWN")
                report.append(f"[{severity}] {vuln.get('plugin_name', 'Unknown')}")
                report.append(f"  Host: {vuln.get('host', 'Unknown')}")
                report.append(f"  Plugin ID: {vuln.get('plugin_id', 'Unknown')}")
                report.append("")
        
        report.append("=" * 60)
        return "\n".join(report)
    
    def save_results_to_file(self, filename: str, content: str, format_type: str = "txt") -> bool:
        """
        Save scan results or reports to a file.
        
        Args:
            filename: Output filename
            content: Content to save
            format_type: File format ("txt", "json", "xml")
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"[+] Results saved to {filename}")
            return True
        except Exception as e:
            print(f"[!] Error saving results to file: {e}")
            return False
    
    def quick_scan(self, target: str, wait_for_completion: bool = True, 
                  generate_report: bool = True) -> Optional[Dict]:
        """
        Perform a complete scan workflow: launch scan, wait for completion, get results.
        
        Args:
            target: Target IP address or hostname
            wait_for_completion: Whether to wait for scan completion
            generate_report: Whether to generate a summary report
            
        Returns:
            Parsed scan results or None if error
        """
        print(f"[*] Starting quick scan of target: {target}")
        
        # Launch scan
        scan_id = self.scan_target(target)
        if not scan_id:
            return None
        
        # Wait for completion if requested
        if wait_for_completion:
            if not self.wait_for_scan_completion(scan_id):
                return None
            
            # Get results
            results = self.get_scan_results(scan_id, "json")
            if not results:
                return None
            
            # Parse results
            parsed_results = self.parse_json_results(results)
            
            # Generate report if requested
            if generate_report and parsed_results:
                report = self.generate_summary_report(parsed_results)
                print("\n" + report)
            
            return parsed_results
        else:
            print(f"[*] Scan launched. Use get_scan_status('{scan_id}') to check progress.")
            return None


if __name__ == "__main__":
    # Example usage
    nessus = NessusExecutor()
    
    # Example target IP - replace with actual target
    target_ip = "192.168.1.100"
    
    print(f"Starting Nessus scan of {target_ip}")
    results = nessus.quick_scan(target_ip)
    
    if results:
        print(f"\nScan completed. Found {results.get('vulnerability_count', 0)} vulnerabilities.")
        
        # Save detailed results
        if nessus.last_scan_results:
            nessus.save_results_to_file(f"nessus_scan_{target_ip}.json", 
                                      nessus.last_scan_results, "json")
        
        # Save summary report
        report = nessus.generate_summary_report(results)
        nessus.save_results_to_file(f"nessus_report_{target_ip}.txt", report, "txt")
