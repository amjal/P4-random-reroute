#!/usr/bin/env python3
import sys

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
	get_if_list,
	sniff,
	conf
)
from scapy.layers.inet import _IPOption_HDR
import socket

received_packets = 0
flow_finished = False

def get_if():
	ifs=get_if_list()
	iface=None
	for i in get_if_list():
		if "eth0" in i:
			iface=i
			break;
	if not iface:
		print("Cannot find eth0 interface")
		exit(1)
	return iface

def handle_pkt(pkt):
	global flow_finished, received_packets
	# The load is usually the sequence number 
	load = pkt[UDP].payload.load.decode("UTF-8")
	print(load)
	if flow_finished == True:
		print("delivery rate: " + str(received_packets) + " / " + 
				str(load) + "  " + str(received_packets/int(load)*100) +"%")
		flow_finished = False
		received_packets = 0
	elif load == "-1":
		flow_finished = True
	else:
		received_packets += 1

def main():
	# Only dissect IP and UDP for better performance
	conf.layers.filter([IP, UDP])
	iface = get_if()
	print("sniffing on %s" % iface)
	sys.stdout.flush()
	sniff(filter="udp and port 4321", iface = iface,
		  prn = handle_pkt)

if __name__ == '__main__':
	main()
