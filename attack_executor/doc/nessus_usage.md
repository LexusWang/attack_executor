# Nessus Scanner Tool Documentation

## Overview

The `NessusExecutor` class provides a comprehensive Python interface for interacting with Nessus vulnerability scanners. This tool allows you to programmatically launch scans, monitor their progress, retrieve results, and generate reports.

## Features

- **Automated Scan Management**: Launch, monitor, and retrieve vulnerability scans
- **Policy Management**: Create and manage scan policies
- **Result Parsing**: Parse JSON/XML scan results into structured data
- **Report Generation**: Generate human-readable summary reports
- **File Operations**: Save results and reports to various formats
- **Error Handling**: Robust error handling and status monitoring

## Prerequisites

### Nessus Installation

1. **Install Nessus**: Download and install Nessus from [Tenable's website](https://www.tenable.com/products/nessus)
2. **Nessus CLI**: Ensure the Nessus CLI (`nessuscli`) is available in your system PATH
3. **License**: Configure Nessus with appropriate licensing (Home, Professional, or Manager)

### System Requirements

- Python 3.11 or higher
- Nessus Professional or Manager (for automated scanning)
- Network access to target systems
- Sufficient disk space for scan results

## Installation

The Nessus tool is part of the `attack_executor` package:

```bash
pip install attack_executor
```

Or if developing locally:

```bash
cd attack_executor
pip install -e .
```

## Basic Usage

### Quick Scan Example

```python
from attack_executor.scan.nessus import NessusExecutor

# Initialize the scanner
nessus = NessusExecutor()

# Perform a quick scan
target_ip = "192.168.1.100"
results = nessus.quick_scan(target_ip)

if results:
    print(f"Scan completed. Found {results['vulnerability_count']} vulnerabilities.")
```

### Step-by-Step Scanning

```python
from attack_executor.scan.nessus import NessusExecutor

# Initialize
nessus = NessusExecutor()

# 1. Launch scan
scan_id = nessus.scan_target("192.168.1.100")

# 2. Monitor progress
while True:
    status = nessus.get_scan_status(scan_id)
    if "completed" in status.lower():
        break
    time.sleep(30)

# 3. Get results
results = nessus.get_scan_results(scan_id, format_type="json")

# 4. Parse and analyze
parsed_results = nessus.parse_json_results(results)

# 5. Generate report
report = nessus.generate_summary_report(parsed_results)
print(report)
```

## Class Methods

### Core Scanning Methods

#### `scan_target(target, policy_name="Basic Network Scan", scan_name=None)`
Launch a vulnerability scan against a target.

**Parameters:**
- `target` (str): IP address or hostname to scan
- `policy_name` (str): Scan policy to use
- `scan_name` (str, optional): Custom name for the scan

**Returns:** Scan ID string or None if failed

#### `get_scan_status(scan_id=None)`
Check the status of a running scan.

**Parameters:**
- `scan_id` (str, optional): Scan ID (uses last scan if not provided)

**Returns:** Status string or None if error

#### `wait_for_scan_completion(scan_id=None, check_interval=30, max_wait=3600)`
Wait for a scan to complete with timeout.

**Parameters:**
- `scan_id` (str, optional): Scan ID to monitor
- `check_interval` (int): Seconds between status checks
- `max_wait` (int): Maximum wait time in seconds

**Returns:** True if completed, False if timeout/error

#### `get_scan_results(scan_id=None, format_type="json")`
Retrieve scan results in specified format.

**Parameters:**
- `scan_id` (str, optional): Scan ID
- `format_type` (str): Output format ("json", "xml", "csv")

**Returns:** Results string or None if error

### Policy Management

#### `list_policies()`
List all available scan policies.

**Returns:** List of policy dictionaries

#### `create_basic_scan_policy(policy_name="Basic Network Scan")`
Create a basic network scan policy.

**Parameters:**
- `policy_name` (str): Name for the new policy

**Returns:** True if successful, False otherwise

### Result Processing

#### `parse_json_results(json_results=None)`
Parse JSON scan results into structured format.

**Parameters:**
- `json_results` (str, optional): JSON results string

**Returns:** Dictionary with parsed scan data

#### `generate_summary_report(scan_results=None)`
Generate human-readable summary report.

**Parameters:**
- `scan_results` (dict, optional): Parsed scan results

**Returns:** Formatted report string

#### `save_results_to_file(filename, content, format_type="txt")`
Save results or reports to file.

**Parameters:**
- `filename` (str): Output filename
- `content` (str): Content to save
- `format_type` (str): File format

**Returns:** True if successful, False otherwise

### Convenience Methods

#### `quick_scan(target, wait_for_completion=True, generate_report=True)`
Perform complete scan workflow in one call.

**Parameters:**
- `target` (str): Target IP or hostname
- `wait_for_completion` (bool): Wait for scan to finish
- `generate_report` (bool): Generate summary report

**Returns:** Parsed scan results or None

## Advanced Usage Examples

### Custom Policy Scanning

```python
nessus = NessusExecutor()

# Create custom policy
nessus.create_basic_scan_policy("Custom Web Scan")

# Scan with custom policy
scan_id = nessus.scan_target("10.0.0.1", policy_name="Custom Web Scan")
```

### Batch Scanning

```python
nessus = NessusExecutor()
targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]

scan_ids = []
for target in targets:
    scan_id = nessus.scan_target(target)
    if scan_id:
        scan_ids.append((target, scan_id))

# Monitor all scans
for target, scan_id in scan_ids:
    nessus.wait_for_scan_completion(scan_id)
    results = nessus.get_scan_results(scan_id)
    nessus.save_results_to_file(f"scan_{target}.json", results)
```

### Result Analysis

```python
nessus = NessusExecutor()
results = nessus.quick_scan("192.168.1.100")

if results:
    # Analyze vulnerabilities by severity
    critical_vulns = [v for v in results['vulnerabilities'] if v['severity'] == 4]
    high_vulns = [v for v in results['vulnerabilities'] if v['severity'] == 3]
    
    print(f"Critical vulnerabilities: {len(critical_vulns)}")
    print(f"High vulnerabilities: {len(high_vulns)}")
    
    # Show critical vulnerabilities
    for vuln in critical_vulns:
        print(f"CRITICAL: {vuln['plugin_name']} on {vuln['host']}")
```

## Configuration

### Environment Variables

- `NESSUS_PATH`: Custom path to Nessus CLI executable
- `NESSUS_CONFIG`: Path to Nessus configuration file

### Custom Nessus Path

```python
# Use custom Nessus installation path
nessus = NessusExecutor(nessus_path="/opt/nessus/bin/nessuscli")
```

## Output Formats

### Parsed Results Structure

```python
{
    'scan_info': {
        'name': 'Scan_192.168.1.100_1234567890',
        'start_time': '2024-01-01T10:00:00Z',
        'end_time': '2024-01-01T11:30:00Z',
        'target': '192.168.1.100'
    },
    'host_count': 1,
    'vulnerability_count': 25,
    'hosts': [
        {
            'ip': '192.168.1.100',
            'os': 'Linux Kernel 5.4',
            'critical_vulns': 2,
            'high_vulns': 5,
            'medium_vulns': 10,
            'low_vulns': 8,
            'info_vulns': 0
        }
    ],
    'vulnerabilities': [
        {
            'host': '192.168.1.100',
            'plugin_id': '12345',
            'plugin_name': 'SSH Weak Encryption Algorithms Supported',
            'severity': 2,
            'description': 'The remote SSH server...'
        }
    ]
}
```

## Error Handling

The tool includes comprehensive error handling:

- **Connection Errors**: Network connectivity issues
- **Authentication Errors**: Invalid Nessus credentials
- **Timeout Errors**: Long-running scan timeouts
- **Permission Errors**: Insufficient privileges
- **File I/O Errors**: Result saving failures

## Best Practices

1. **Resource Management**: Monitor scan progress to avoid resource exhaustion
2. **Rate Limiting**: Don't launch too many concurrent scans
3. **Target Validation**: Ensure you have permission to scan targets
4. **Result Storage**: Save results promptly after scan completion
5. **Security**: Store Nessus credentials securely

## Troubleshooting

### Common Issues

**Nessus CLI Not Found**
```bash
# Add Nessus to PATH
export PATH=$PATH:/opt/nessus/bin
```

**Permission Denied**
```bash
# Check Nessus service status
sudo systemctl status nessusd

# Restart if needed
sudo systemctl restart nessusd
```

**Scan Failures**
- Verify target accessibility
- Check network connectivity
- Ensure sufficient Nessus licenses
- Review scan policy settings

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

nessus = NessusExecutor()
# Debug output will show detailed command execution
```

## Integration Examples

### With Other Attack Executor Tools

```python
from attack_executor.scan.nmap import NmapExecutor
from attack_executor.scan.nessus import NessusExecutor

# Initial port scan
nmap = NmapExecutor()
ports = nmap.scan_xml("192.168.1.100")

# Detailed vulnerability scan
nessus = NessusExecutor()
results = nessus.quick_scan("192.168.1.100")
```

### With Automation Frameworks

```python
import schedule
import time

def daily_scan():
    nessus = NessusExecutor()
    targets = ["192.168.1.100", "192.168.1.101"]
    
    for target in targets:
        results = nessus.quick_scan(target)
        if results:
            # Send alert if critical vulnerabilities found
            critical_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 4)
            if critical_count > 0:
                send_alert(f"Critical vulnerabilities found on {target}")

# Schedule daily scans
schedule.every().day.at("02:00").do(daily_scan)
```

## License and Legal Considerations

- Ensure you have proper authorization before scanning any systems
- Comply with your organization's security policies
- Respect rate limits and resource constraints
- Nessus licensing requirements apply for commercial use

## Support

For issues and questions:
- Check the [Attack Executor GitHub repository](https://github.com/your-repo/attack_executor)
- Review Nessus documentation at [Tenable Support](https://docs.tenable.com/)
- Follow responsible disclosure practices for any security issues found 