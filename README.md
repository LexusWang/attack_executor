# Attack Executor

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
## Metasploit

### Installation
#### Install Metasploit

```
$ msfconsole
msf> load msgrpc [Pass=yourpassword]
```


