<!-- [![Release](https://img.shields.io/badge/dynamic/json?color=blue&label=Release&query=tag_name&url=https%5B%5D)](https:%5B%5D) -->
![License](https://img.shields.io/github/license/LexusWang/attack_executor)

# Attack Executor
Attack Executor is a standardized toolkit for conducting cyberattacks and penetration testing. Our goal is to define a standardized approach to use the common tools involved in cyberattacks and penetration tests, thereby increasing the efficiency of attack execution and prepare for an LLM Agent capable of automated penetration testing and red-team simulations.

For now, Attack Executor supports the following penetration testing and red teaming tools:
- Scanning
    - Nmap
    - Gobuster
- Exploitation
    - Searchsploit
    - [Metasploit](#metasploit)
- Privilege Escalation
    - Linpeas
- Post-exploitation
    - [Sliver](#sliver)


## Installation
In order to use Attack Executor, please install the Python package using
```
pip install attack-executor
```

You also need to install the tools that will be used by Attack Executor.
Details can be found here:
- [Metasploit](#metasploit)
- [Sliver](#sliver)
- Nmap
- Searchsploit

We are preparing and will provide a script to automatically install all dependencies.

## Sliver

### Installation
#### Install Sliver-server
Download sliver-server bin from [their webite](https://github.com/BishopFox/sliver/releases)

```
$ ./sliver-server

sliver > new-operator --name zer0cool --lhost localhost --lport 34567 --save ./zer0cool.cfg
[*] Generating new client certificate, please wait ...
[*] Saved new client config to: /Users/zer0cool/zer0cool.cfg

sliver > multiplayer --lport 34567
[*] Multiplayer mode enabled!
```

Then, modify the related entries in `config.ini`:
```
[sliver]
client_config_file = /home/user/Downloads/zer0cool.cfg
```

## Metasploit

### Installation
#### Install Metasploit

```
$ msfconsole
msf> load msgrpc [Pass=yourpassword]
[*] MSGRPC Service:  127.0.0.1:55552 
[*] MSGRPC Username: msf
[*] MSGRPC Password: glycNshR
[*] Successfully loaded plugin: msgrpc
```

Then, modify the related entries in `config.ini`:
```
[metasploit]
password = glycNshR
host_ip = 127.0.0.1
listening_port = 55552
```

## Searchsploit

### Installation

Searchsploit is part of the ExploitDB project and is required for exploit searching functionality.

- **On Kali Linux / Parrot OS:**
  Searchsploit is usually pre-installed. If not, install it with:
  ```
  sudo apt update && sudo apt install exploitdb
  ```
- **On other Debian/Ubuntu-based systems:**
  ```
  sudo apt update && sudo apt install exploitdb
  ```
- **On macOS (using Homebrew):**
  ```
  brew install exploitdb
  ```
- **Manual installation and more info:**
  See the official ExploitDB repository: https://github.com/offensive-security/exploitdb

After installation, ensure the `searchsploit` command is available in your PATH by running:
```
searchsploit -h
```


