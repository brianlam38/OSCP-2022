## Recon

Rustscan to identify ports + Nmap for service info
```
$ rustscan -a [ip1, ip2]                                     # scan all addresses
$ nmap -v -sSV -p [port1, port2] -Pn [host] -oN [filename]   # verbose, syn-stealth, svc versions, target ports, no-ping,
$ nmap -v -sUV -p [port1, port2] -Pn [host] -oN [filename]   # UDP
```
