#!/usr/bin/python2
#xsvest05 | KRY - 1. project | VUT FIT
#MAIN FILE

import os
import sys
import re
import optparse
import binascii
from Crypto.Cipher import AES
import hashlib
from dh import DiffieHellman
from pipe import Pipe
from ffs import FFS
import base64

############################# Turn on debug mode ####
DEBUG_MODE = False
#show exchanging messages
DEBUG_MODE_MORE = False
############################# Turn on debug mode ####


#global
dh = DiffieHellman()
pipe = Pipe()

def debug(msg, more=False):
	"""
	Only for debugging
	@param string message
	"""
	if DEBUG_MODE and not more:
		print msg
		print "--"
		sys.stdout.flush()
	if more and DEBUG_MODE_MORE:
		print msg
		print "--"
		sys.stdout.flush()


def dhServer():
	"""
	Diffie-Hellman steps for server
	"""
	global dh, pipe

	debug("My private exponent is '" + str(dh.privateKey) + "'\nlength: " + str(bit_length(dh.getPrivateKey())))

	#send X
	pipe.write(str(dh.getPublicKey()))
	debug("Sent X='" + str(dh.getPublicKey()) + "'", True)

	#receive Y
	Y = long(pipe.read())
	dh.genSecret(Y)
	debug("Received Y='" + str(Y) + "'", True)


	debug("Our key is '" + dh.getKey().encode("hex") + "'")

def dhClient():
	"""
	Diffie-Hellman steps for client
	"""
	global dh, pipe

	debug("My private exponent is '" + str(dh.privateKey) + "'\nlength: " + str(bit_length(dh.getPrivateKey())))

	#receive X
	X = long(pipe.read())
	dh.genSecret(X)
	debug("Received X='" + str(X) + "'", True)

	#send Y
	pipe.write(str(dh.getPublicKey()))
	debug("Sent Y='" + str(dh.getPublicKey()) + "'", True)


	debug("Our key is '" + dh.getKey().encode("hex") + "'")


def client():
	"""
	Main loop for client
	"""
	global pipe

	while True:
		try:
			#wait for message
			data = raw_input("Enter your message: ")
		except (KeyboardInterrupt, SystemExit):
			print '\n! exiting...\n'
			encoded = encode("exit")
			pipe.write(encoded)
			return

		myHash = getHash(data)
		print "\tmessage hash: " + myHash

		encoded = encode(data)
		pipe.write(encoded)

		#exiting
		if data == "exit":
			break

		#wait for reply with hash from server
		hashFromServer = decode(pipe.read())

		if myHash != hashFromServer:
			print "\treply from server: hash MISMATCH!!!"
		else:
			print "\treply from server: hash OK"

def server():
	"""
	Main loop for server
	"""
	global pipe

	while True:
		data = decode(pipe.read())

		#exiting
		if data == "exit":
			pipe.close()
			print '\n! exiting...\n'
			break

		#hash
		h = getHash(data)

		print "received: " + data.decode('utf-8')
		print "hash: " + h
		print "--"

		#send hash of message to the client
		pipe.write(encode(h))

def encode(data):
	"""
	Encrypt data
	@source: http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
	"""
	length = 16 - (len(data) % 16)
	data += chr(length)*length

	iv = os.urandom(AES.block_size)
	cipher = AES.new(dh.getKey(), AES.MODE_CBC, iv)
	encoded = base64.b64encode(iv + cipher.encrypt(data))

	return encoded

def decode(data):
	"""
	Decrypt data
	@source: http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
	"""
	enc = base64.b64decode(data)
	iv = enc[:AES.block_size]
	cipher = AES.new(dh.getKey(), AES.MODE_CBC, iv)
	data = cipher.decrypt(enc[AES.block_size:])
	decoded = data[:-ord(data[len(data)-1:])]

	return decoded

def getHash(message):
	"""
	Calculate SHA256 hash of message
	"""
	s = hashlib.sha256()
	s.update(bytes(message))

	return s.hexdigest()

def bit_length(data):
	"""
	Get bit length of data
	@source: https://docs.python.org/2/library/stdtypes.html
	"""
	s = bin(data)       # binary representation:  bin(-37) --> '-0b100101'
	s = s.lstrip('-0b') # remove leading zeros and minus sign
	return len(s)       # len('100101') --> 6

def FFServer(ffs):
	"""
	Feige-Fiat-Shamir for server
	"""
	global pipe

	#receive public key - vector V
	for i in range(0, ffs.getK()):
		v = long(pipe.read())
		debug("received part of vector V: " + str(v), True)
		ffs.appendV(v)
		pipe.sendACK()

	pipe.waitACK()

	#receive X
	X = long(pipe.read())
	debug("received X: " + str(X), True)
	ffs.setX(X)
	pipe.sendACK()

	#send k-bit vector E
	for e in ffs.genVectorE():
		debug("send part of vector E: " + str(e), True)
		pipe.write(str(e))
		pipe.waitACK()

	pipe.sendACK()

	#receive Y
	Y = long(pipe.read())
	debug("received Y: " + str(Y), True)
	ffs.setY(Y)

	#compute Z
	ffs.genZ()
	debug("Z is: " + str(ffs.getZ()), True)

	return ffs.isValid()


def FFSClient(ffs):
	"""
	Feige-Fiat-Shamir for client
	"""
	global pipe

	#generate public key and send it
	for v in ffs.genVectorV():
		debug("send part of vector V: " + str(v), True)
		pipe.write(str(v))
		pipe.waitACK()

	pipe.sendACK()

	#send X
	X = ffs.genX()
	debug("send X: " + str(X), True)
	pipe.write(str(X))
	pipe.waitACK()

	#receive E
	for i in range(0, ffs.getK()):
		e = int(pipe.read())
		debug("received part of vector E: " + str(e), True)
		ffs.appendE(e)
		pipe.sendACK()

	pipe.waitACK()

	#send Y
	Y = ffs.genY()
	debug("send Y: " + str(Y), True)
	pipe.write(str(Y))

def main():
	"""
	Main function
	"""
	global pipe

	#parse arguments
	parser = optparse.OptionParser("usage: %prog -s or -c")
	parser.add_option("-s", "--server", dest="server", action='store_true', help="run as server")
	parser.add_option("-c", "--client", dest="client", action='store_true', help="run as client")

	(options, args) = parser.parse_args()
	
	if options.server and not options.client:
		debug("Hello, I am server")
		ffs = FFS()
		valid = 0
		while True:
			#run 
			if FFServer(ffs):
				valid += 1
				#succeed
				if valid == ffs.getT():
					pipe.write("FFS_OK")
					debug("FFS VALID - step " + str(valid))
					debug("FFS FINISHED - IDENTITY OK")
					break
				#next step
				else:
					debug("FFS VALID - step " + str(valid))
					pipe.write("FFS_NEXT")
					ffs = FFS()
			#failed
			else:
				pipe.write("FFS_BAD")
				debug("FFS BAD - IDENTITY NOT OK")
				return

		#Diffie-Hellman
		dhServer()

		#server loop
		server()
	elif options.client and not options.server:
		debug("Hello, I am client")
		ffs = FFS()
		FFSClient(ffs)
		while True:
			status = pipe.read()

			#next step
			if status == "FFS_NEXT":
				debug("FFS VALID")
				ffs = FFS()
				FFSClient(ffs)
			#succeed
			elif status == "FFS_OK":
				debug("FFS FINISHED - IDENTITY OK")
				break
			#failed
			elif status == "FFS_BAD":
				debug("FFS BAD - IDENTITY NOT OK")
				return

		#Diffie-Hellman
		dhClient()

		#client loop
		client()
	elif options.client and options.server:
		sys.stderr.write("Parameters -c and -s are mutually exclusive\n")
		pipe.close()
		sys.exit(2)

	else:
		#either server or client must be set
		sys.stderr.write("Either -s or -c must be set\n")
		pipe.close()
		sys.exit(2)

if __name__ == "__main__":
	#call main
	main()


