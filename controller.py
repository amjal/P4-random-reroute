# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
# [GCC 9.4.0]
# Embedded file name: /home/p4/randomReroute.p4app/controller.py
# Compiled at: 2022-07-04 20:15:10
# Size of source mod 2**32: 1201 bytes
import json, os, p4runtime_lib.simple_controller

class CustomAppController:

	def __init__(self, *args, **kwargs):
		self.net = kwargs['net']
		self.log_dir = kwargs['log_dir']
		topo_file = kwargs['topo_file']
		with open(topo_file, 'r') as (f):
			topo = json.load(f)
		self.switches = topo['switches']
		self.bmv2_exe = kwargs['sw_path']
		self.cli_path = kwargs['cli_path']

	def program_switch_p4runtime(self, sw_name, sw_dict):
		sw_obj = self.net.get(sw_name)
		port = ''
		if 'grpc' in self.bmv2_exe:
			port = sw_obj.grpc_port
		else:
			port = sw_obj.thrift_port
		device_id = sw_obj.device_id
		runtime_json = sw_dict['runtime_json']
		with open(runtime_json, 'r') as sw_conf_file:
			outfile = '%s/%s-p4runtime-requests.txt' % (self.log_dir, sw_name)
			p4runtime_lib.simple_controller.program_switch(
					addr=("127.0.0.1:"+  str(port)),
			  		device_id=device_id,
					sw_conf_file=sw_conf_file,
					workdir=(os.getcwd()),
					proto_dump_fpath=outfile,
					runtime_json=runtime_json)

	def start(self):
		for sw_name, sw_dict in self.switches.items():
			if 'cli_input' in sw_dict:
				pass
			if 'runtime_json' in sw_dict:
				self.program_switch_p4runtime(sw_name, sw_dict)
