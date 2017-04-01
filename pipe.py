#xsvest05 | KRY | VUT FIT
#Communication in pipes

import os
import errno

#pipe for data
PIPE_NAME = 'xsvest05_pipe'

#pipe for ACK
PIPE_NAME_ACK = 'xsvest05_pipe_ack'

class Pipe(object):

	def __init__(self):
		try:
			os.mkfifo(PIPE_NAME)
		except OSError as oe: 
			if oe.errno != errno.EEXIST:
				raise
		try:
			os.mkfifo(PIPE_NAME_ACK)
		except OSError as oe: 
			if oe.errno != errno.EEXIST:
				raise				

	def write(self, message):
		"""
		Send message
		"""
		pipe = open(PIPE_NAME, "w")
		pipe.write(message)
		pipe.close()

	def read(self):
		"""
		Receive message
		"""
		pipe = open(PIPE_NAME, "r")
		while True:
			data = pipe.read()
			if len(data) == 0:
				pipe.close()
				break

			pipe.close()
			return data

	def sendACK(self):
		"""
		Send ACK
		"""
		pipe = open(PIPE_NAME_ACK, "w")
		pipe.write("")
		pipe.close()


	def waitACK(self):
		"""
		Wait for ACK
		"""
		pipe = open(PIPE_NAME_ACK, "r")
		data = pipe.read()
		pipe.close()


	def close(self):
		os.remove(PIPE_NAME)
		os.remove(PIPE_NAME_ACK)