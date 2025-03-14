# Attack Executor
Attack Executor is a standardized toolkit for conducting cyberattacks and penetration testing. Our goal is to define a standardized approach to use the common tools involved in cyberattacks and penetration tests, thereby increasing the efficiency of attack execution and prepare for an LLM Agent capable of automated penetration testing and red-team simulations.

## Installation
In order to use Attack Executor, please install the Python package using
```
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple attack-executor==0.1.2
```

You also need to install the tools that will be used by Attack Executor. For now, Attack Executor supports the following tools:
- [Metasploit](#metasploit)
- [Sliver](#sliver)
- Nmap

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


