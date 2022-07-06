import json

class CustomAppProcRunner:
	def __init__(self, net, *args, **kwargs):
		manifest, target = kwargs['manifest'], kwargs['target']
		target_config = manifest['targets'][target]

		with open(target_config['topo_file']) as f:
			topo = json.load(f)

		self.hosts = topo['hosts']
		self.net = net

	def program_hosts(self):
		for host in self.hosts:
			node = self.net.getNodeByName(host)
			for cmd in self.hosts[host]['commands']:
				node.cmd(cmd)
