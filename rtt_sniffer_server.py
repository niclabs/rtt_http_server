import threading
import signal

import socket
import struct
import binascii
import time

import sys
import wsgiserver

class MyThreadSniffer(threading.Thread):
	def __init__(self, lock, cond, ips, sniff_port):
		threading.Thread.__init__(self)
		self.lock = lock
		self.cond = cond
		self.ips = ips
		self.sniff_port = sniff_port
		self.still_running = True

	def stop(self):
		self.still_running = False

	def is_ack(self, flags):
		return 16&flags>0

	def is_syn(self, flags):
		return 2&flags>0

	def is_psh(self, flags):
		return 8&flags>0

	def is_fin(self, flags):
		return 1&flags>0

	def run(self):
		# creating a rawSocket for communications
		# PF_SOCKET (packet interface), SOCK_RAW (Raw socket) - htons (protocol) 0x08000 = IP Protocol
		print("prev socket create")
		rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
		rawSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		print("Sniffing on port:", self.sniff_port)
		while self.still_running:
			# read a packet with recvfrom method
			pkt = rawSocket.recvfrom(2048) # tuple return

			# Ethernet Header tuple segmentation
			eHeader = pkt[0][0:14]

			# parsing using unpack
			eth_hdr = struct.unpack("!6s6s2s", eHeader) # 6 dest MAC, 6 host MAC, 2 ethType

			# using hexify to convert the tuple value NBO into Hex format
			binascii.hexlify(eth_hdr[0])
			binascii.hexlify(eth_hdr[1])
			binascii.hexlify(eth_hdr[2])

			ipHeader = pkt[0][14:34]
			ip_hdr = struct.unpack("!12s4s4s", ipHeader) # 12s represents Identification, Time to Live, Protocol | Flags, Fragment Offset, Header Checksum
			src_ip = socket.inet_ntoa(ip_hdr[1])
			dst_ip = socket.inet_ntoa(ip_hdr[2])
			
			# unapck the TCP header (source and destination port numbers)
			tcpHeader = pkt[0][34:54]
			#print("strlen(tcpHeader)",len(tcpHeader))
			tcp_hdr = struct.unpack("!2H2L2BHHH", tcpHeader)

			src_port = tcp_hdr[0]
			dst_port = tcp_hdr[1]
			
			seq_num = tcp_hdr[2]
			ack_num = tcp_hdr[3]
			
		#	reserved = tcp_hdr[4]
			flags = tcp_hdr[5]
		#	window = tcp_hdr[6]
		#	checksum = tcp_hdr[7]
		#	urgent_pointer = tcp_hdr[8]
			

			if dst_port == self.sniff_port:
				key = dst_ip+str(src_port)#key to use in dict
				if self.is_syn(flags) and not self.is_ack(flags): #Syn
					#save start time
					start_time = time.time()
					#save seq number
					self.lock.acquire()
					self.ips[key] = {}
					self.ips[key]["start_time"] = start_time
					self.ips[key]["status"] = "SYN"
					self.ips[key]["last_seq_num"] = seq_num
					self.lock.release()

				elif self.is_ack(flags) and not self.is_syn(flags): #Ack
					#verify ack number is = to previous seq number
					if key not in ips:
						continue

					self.lock.acquire()
					if self.ips[key]["last_seq_num"]+1 == ack_num and ips[key]["status"] != "ACK":
						#save end time
						end_time = time.time()
						#calculate RTT
						self.ips[key]["status"] = "ACK"
						rtt = end_time-self.ips[key]["start_time"]
						#save RTT and src ip
						self.ips[key]["rtt"] = rtt
					self.cond.notify()
					self.lock.release()


			elif src_port == self.sniff_port:	

				key = src_ip+str(dst_port)

				self.lock.acquire()
				if key not in self.ips:
					continue		
				if self.is_syn(flags) and self.is_ack(flags) : #Syn + Ack
					#verify ack number is = to saved seq number
					if self.ips[key]["last_seq_num"]+1 == ack_num:
						#save seq number
						self.ips[key]["last_seq_num"] = seq_num
						self.ips[key]["status"] = "SYN+ACK"
				self.lock.release()
		rawSocket.close()
		print("thread stop running")
#ends thread class						  


if __name__ == '__main__':






	##starts http server
	if len(sys.argv)!=3:
	    print('Usage: python ping_tcp_server.py <ip_addr> <port>')
	host = str(sys.argv[1])
	port = int(sys.argv[2])


	#args to start thread
	lock = threading.Lock()
	cond = threading.Condition(lock)
	ips = {}
	thread = MyThreadSniffer(lock, cond, ips, port)
	thread.setDaemon(True)
	thread.start() 

	def handler(signum, frame):
		print("Waiting for thread...")
		thread.stop()
		thread.join()
		print("sniffer thread closed")
		exit()

	signal.signal(signal.SIGINT, handler)

	##http server stuff

	def my_rtt(environ, start_response):
	    status = '200 OK'
	    response_headers = [('Content-type','json')]
	    start_response(status, response_headers)
	    print(environ['REMOTE_ADDR'], environ['REMOTE_PORT'])
	    rtt, err  = get_rtt(environ['REMOTE_ADDR'], environ['REMOTE_PORT'])
	    if err != None:
	    	return ['Opps some error ocurred :(']

	    return [str(rtt)]

	def get_rtt(ip, port):
		#TODO get rtt
		key = ip+port
		cond.acquire()
		while key not in ips:
			cond.wait()
			#sleep	
		while "rtt" not in ips[key]:
			cond.wait()	
		rtt = ips[key]["rtt"] ##check if ip exists and status
		cond.release()
		return rtt, None
		err = "Error"
		return None, err





	d = wsgiserver.WSGIPathInfoDispatcher({'/rtt': my_rtt})
	server = wsgiserver.WSGIServer(d, host=host, port=port)

	#To add SSL support, just specify a certfile and a keyfile
	#server = wsgiserver.WSGIServer(my_app, certfile='cert.pem', keyfile='privkey.pem')
	print("Server running on: ", host, port)
	server.start()
	print("server stopped")
