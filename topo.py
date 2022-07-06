# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
# [GCC 9.4.0]
# Embedded file name: /home/p4/randomReroute.p4app/topo.py
# Compiled at: 2022-07-05 14:13:52
# Size of source mod 2**32: 3091 bytes
from mininet.topo import Topo
import json

class CustomTopo(Topo):

	def __init__(self, hosts, switches, links, log_dir, sw_path, pcap_dir, **opts):
		Topo.__init__(self, **opts)
		host_links = []
		switch_links = []
		for link in links:
			if link['node1'][0] == 'h':
				host_links.append(link)
			else:
				switch_links.append(link)

		for sw, params in switches.items():
			self.addSwitch(sw, log_file=('%s/%s.log' % (log_dir, sw)))

		for link in host_links:
			host_name = link['node1']
			sw_name, sw_port = self.parse_switch_node(link['node2'])
			host_ip = hosts[host_name]['ip']
			host_mac = hosts[host_name]['mac']
			self.addHost(host_name, ip=host_ip, mac=host_mac)
			self.addLink(host_name, sw_name, delay=(link['latency']),
			  bw=(link['bandwidth']),
			  port2=sw_port)

		for link in switch_links:
			sw1_name, sw1_port = self.parse_switch_node(link['node1'])
			sw2_name, sw2_port = self.parse_switch_node(link['node2'])
			self.addLink(sw1_name, sw2_name, port1=sw1_port,
			  port2=sw2_port,
			  delay=(link['latency']),
			  bw=(link['bandwidth']))

	def parse_switch_node(self, node):
		assert (len(node.split('-')) == 2)
		sw_name, sw_port = node.split('-')
		try:
			sw_port = int(sw_port[1:])
		except:
			raise Exception('Invalid switch nodd in topology file: {}'.format(node))
		return sw_name, sw_port


class CustomAppTopo:

	def logger(self, *items):
		if not self.quiet:
			print(' '.join(items))

	def format_latency(self, l):
		if isinstance(l, str):
			return l
		return str(l) + 'ms'

	def __init__(self, log_dir, pcap_dir, sw_path, quiet=True, *args, **kwargs):
		manifest, target = kwargs['manifest'], kwargs['target']
		target_config = manifest['targets'][target]
		self.quiet = quiet
		self.logger('Reading topology file')
		with open(target_config['topo_file']) as (f):
			topo = json.load(f)
		self.hosts = topo['hosts']
		self.switches = topo['switches']
		self.links = self.parse_links(topo['links'])
		self.log_dir = log_dir
		self.pcap_dir = pcap_dir
		self.sw_path = sw_path

	def parse_links(self, unparsed_links):
		links = []
		for link in unparsed_links:
			s, t = link[0], link[1]
			if s > t:
				s, t = t, s
			link_dict = {'node1':s, 
			 'node2':t,  'latency':'0ms',  'bandwidth':None}
			if len(link) > 2:
				link_dict['latency'] = self.format_latency(link[2])
			if len(link) > 3:
				link_dict['bandwidth'] = link[3]
			if link_dict['node1'][0] == 'h':
				assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])
			links.append(link_dict)
		return links

	def create_network(self):
		self.logger('Building mininet topology.')
		return CustomTopo(self.hosts, self.switches, self.links, self.log_dir, self.sw_path, self.pcap_dir)
