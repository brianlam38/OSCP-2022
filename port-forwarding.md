# Port Forwarding Techniques

### Dynamic Port Forwarding

This will allow you to access internal network services on dynamic (as opposed to static) ports.

Setup
1. Ensure `/etc/proxychains4.conf` is setup with the preferred port (deafult is `9050`).
2. Establish SSH tunnel with proxy server `$ kali> sudo ssh -N -D 127.0.0.1:9050 username@proxy_server/jump_box`

Directory brute-force example
* Wfuzz works well, Gobuster requires some setup.
```
wfuzz -p 127.0.0.1:9050:SOCKS4 -c -w [/path/to/wordlist] --hc=404 http://[internal_target]/FUZ
```
