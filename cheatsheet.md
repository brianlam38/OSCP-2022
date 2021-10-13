## Recon

Rustscan to identify ports + Nmap for service info
```
$ rustscan -a [ip1, ip2]                        # scan all addresses
$ nmap -v -sSV -p [port1, port2] 10.10.10.XXX   # verbose, syn-stealth, service versions, target ports
$ nmap -v -sUV -p [port1, port2] 10.10.10.XXX   # UDP
```
