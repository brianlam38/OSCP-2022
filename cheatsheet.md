## Recon

Rustscan scan all hosts + Nmap for service info on each
```
$ rustscan -a [host, host]                                   # scan all addresses
$ nmap -v -sSV -p [port1, port2] -Pn [host] -oN [filename]   # verbose, syn-stealth, svc versions, target ports, no-ping,
$ nmap -v -sUV -p [port1, port2] -Pn [host] -oN [filename]   # UDP
```
