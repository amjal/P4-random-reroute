#!/usr/bin/env python3

import socket
import sys
from time import sleep
from time import time

from scapy.all import (
	IP,
	UDP,
	Ether,
	FieldLenField,
	IntField,
	IPOption,
	Packet,
	PacketListField,
	ShortField,
	get_if_hwaddr,
	get_if_list,
	sendp,
	conf
)
from scapy.layers.inet import _IPOption_HDR
import socket

def get_if():
	ifs=get_if_list()
	iface=None
	for i in get_if_list():
		if "eth0" in i:
			iface = i
			break;
	if not iface:
		print("Cannot find eth0 interface")
		exit(1)
	return iface

def create_pkts(base_pkt, total_bits, bit_delay):
	pkt_list = []
	bits_sent = 0
	seq_no = 0
	while bits_sent < total_bits:
		pkt = base_pkt / str(seq_no)
		packet_size = len(pkt)*8
		pkt_list.append((pkt.build(), packet_size*bit_delay))
		bits_sent += packet_size
		seq_no += 1
	return pkt_list


def main():
	if len(sys.argv)<4:
		print('pass 3 arguments: <destination> <duration> <bandwidth>')
		exit(1)

	addr = socket.gethostbyname(sys.argv[1])
	iface = get_if()
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	sock.bind((iface, 0))

	base_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP( dst=addr, options = IPOption(copy_flag = 0, optclass=0, option = 31, length = 3, value=0)) / UDP( dport=4321, sport=1234)
	
	#pkt.show2()
	#hexdump(pkt)
	duration = float(sys.argv[2])
	bandwidth = float(sys.argv[3])
	total_bits = duration*bandwidth
	#Time interval between two bits
	bit_delay = 1/bandwidth
	#first create the packets
	pkt_list = create_pkts(base_pkt, total_bits, bit_delay)
	# Using a socket for sending will make things way faster	
	print(len(pkt_list))
	s = conf.L2socket()
	sss = time()
	for pkt, pkt_delay in pkt_list:
		start = time()
		sock.send(pkt)
#sendp(pkt, iface=iface, verbose=False)
		end = time()
		dur = end - start
		# dur which is about 0.001s is the time it 
		# takes the library to send a packet which we then offset
		start = time()
		# sleep is inaccurate therefore we have this spin lock
		while (time() - start < pkt_delay - dur):
			pass
	print(time() - sss)
	print("flow finished")
	# Sleep to make sure congestion goes away before sending the two control packets
	# Send a negative seq no at the end to let server know
	pkt = base_pkt / str(-1)
	sendp(pkt, iface=iface, verbose=False)
	# After that send the number of packets you sent 
	pkt = base_pkt / str(len(pkt_list))
	sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
	main()
