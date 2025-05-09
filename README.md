<!-- [![Release](https://img.shields.io/badge/dynamic/json?color=blue&label=Release&query=tag_name&url=https%5B%5D)](https:%5B%5D) -->
[![PyPI version](https://img.shields.io/pypi/v/attack-executor.svg)](https://pypi.org/project/attack-executor/)
![License](https://img.shields.io/github/license/LexusWang/attack_executor)

# Attack Executor
Attack Executor is a standardized toolkit for conducting cyberattacks and penetration testing. Our goal is to define a standardized approach to use the common tools involved in cyberattacks and penetration tests, thereby increasing the efficiency of attack execution and prepare for an LLM Agent capable of automated penetration testing and red-team simulations.

For now, Attack Executor supports the following penetration testing and red teaming tools:
- Scanning
    - [Nmap](https://nmap.org/)
    - [Nuclei](https://github.com/projectdiscovery/nuclei)
    - [Gobuster](https://github.com/OJ/gobuster)
- Exploitation
    - Searchsploit
    - Exploit modules from [Metasploit](#metasploit)
- Privilege Escalation
    - Linpeas
- Post-exploitation
    - [Sliver](#sliver)


## Installation
In order to use Attack Executor, please install the Python package using
```bash
pip install attack-executor
```

You also need to install the tools that will be used by Attack Executor.
Details can be found here:
- Nmap
- Nuclei
- Gobuster
- [Metasploit](#metasploit)
- [Sliver](#sliver)

We are preparing and will provide a script to automatically install all dependencies.

You can run this command to check the installation of the tools
```bash
attack_executor --check_install
```

## Sliver

### Installation
#### Install Sliver-server
Download sliver-server bin from [their webite](https://github.com/BishopFox/sliver/releases)

```bash
$ ./sliver-server

sliver > new-operator --name zer0cool --lhost localhost --lport 34567 --save ./zer0cool.cfg
[*] Generating new client certificate, please wait ...
[*] Saved new client config to: /Users/zer0cool/zer0cool.cfg

sliver > multiplayer --lport 34567
[*] Multiplayer mode enabled!
```

Then, modify the related entries in `config.ini`:
```ini
[sliver]
client_config_file = /home/user/Downloads/zer0cool.cfg
```

## Metasploit

### Installation
#### Install Metasploit

```bash
$ msfconsole
msf> load msgrpc [Pass=yourpassword]
[*] MSGRPC Service:  127.0.0.1:55552 
[*] MSGRPC Username: msf
[*] MSGRPC Password: glycNshR
[*] Successfully loaded plugin: msgrpc
```

Then, modify the related entries in `config.ini`:
```ini
[metasploit]
password = glycNshR
host_ip = 127.0.0.1
listening_port = 55552
```


