#!/usr/bin/env python3
#
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import argparse
import json
import os
import sys
import subprocess



def error(msg):
	print (' - ERROR! ' + msg)

def info(msg):
	print (' - ' + msg)


class ConfException(Exception):
	pass


def main():
	parser = argparse.ArgumentParser(description='P4Runtime Simple Controller')

	parser.add_argument('-a', '--p4runtime-server-addr',
						help='address and port of the switch\'s P4Runtime server (e.g. 192.168.0.1:50051)',
						type=str, action="store", required=True)
	parser.add_argument('-d', '--device-id',
						help='Internal device ID to use in P4Runtime messages',
						type=int, action="store", required=True)
	parser.add_argument('-p', '--proto-dump-file',
						help='path to file where to dump protobuf messages sent to the switch',
						type=str, action="store", required=True)
	parser.add_argument("-c", '--runtime-conf-file',
						help="path to input runtime configuration file (JSON)",
						type=str, action="store", required=True)

	args = parser.parse_args()

	if not os.path.exists(args.runtime_conf_file):
		parser.error("File %s does not exist!" % args.runtime_conf_file)
	workdir = os.path.dirname(os.path.abspath(args.runtime_conf_file))
	with open(args.runtime_conf_file, 'r') as sw_conf_file:
		program_switch(addr=args.p4runtime_server_addr,
					   device_id=args.device_id,
					   sw_conf_file=sw_conf_file,
					   workdir=workdir,
					   proto_dump_fpath=args.proto_dump_file)


def check_switch_conf(sw_conf, workdir):
	required_keys = ["p4info"]
	files_to_check = ["p4info"]
	target_choices = ["bmv2"]

	if "target" not in sw_conf:
		raise ConfException("missing key 'target'")
	target = sw_conf['target']
	if target not in target_choices:
		raise ConfException("unknown target '%s'" % target)

	if target == 'bmv2':
		required_keys.append("bmv2_json")
		files_to_check.append("bmv2_json")

	for conf_key in required_keys:
		if conf_key not in sw_conf or len(sw_conf[conf_key]) == 0:
			raise ConfException("missing key '%s' or empty value" % conf_key)

	for conf_key in files_to_check:
		real_path = os.path.join(workdir, sw_conf[conf_key])
		if not os.path.exists(real_path):
			raise ConfException("file does not exist %s" % real_path)


def program_switch(cli_path, thrift_port, device_id, sw_conf_file, workdir, proto_dump_fpath, runtime_json):
	sw_conf = json_load_byteified(sw_conf_file)
	try:
		check_switch_conf(sw_conf=sw_conf, workdir=workdir)
	except ConfException as e:
		error("While parsing input runtime configuration: %s" % str(e))
		return

	info('Using P4Info file %s...' % sw_conf['p4info'])
	p4info_fpath = os.path.join(workdir, sw_conf['p4info'])

	if 'table_entries' in sw_conf:
		table_entries = sw_conf['table_entries']
		info("Inserting %d table entries..." % len(table_entries))
		for entry in table_entries:
			command = generate_table_add(entry)
			runCommand(cli_path, thrift_port, command)

	if 'multicast_group_entries' in sw_conf:
		group_entries = sw_conf['multicast_group_entries']
		info("Inserting %d group entries..." % len(group_entries))
		for entry in group_entries:
			# First create mcast groups and nodes
			mgrp_command, mcnd_command = generate_group_entry(entry)
			runCommand(cli_path, thrift_port, mgrp_command)
			results = runCommand(cli_path, thrift_port, mcnd_command)
			# Use the handle to associate mcast group with node
			node_handle = 0
			for r in results:
				if 'handle' in r:
					node_handle = r.split(' ')[-1]
			ass_command = generate_associate_cmd(entry, node_handle)
			runCommand(cli_path, thrift_port, ass_command)
			

	if 'clone_session_entries' in sw_conf:
		raise Exception('Clone entries have not been implemeted yet')


def validateTableEntry(flow, p4info_helper, runtime_json):
	table_name = flow['table']
	match_fields = flow.get('match')  # None if not found
	priority = flow.get('priority')  # None if not found
	match_types_with_priority = [
		p4info_pb2.MatchField.TERNARY,
		p4info_pb2.MatchField.RANGE
	]
	if match_fields is not None and (priority is None or priority == 0):
		for match_field_name, _ in match_fields.items():
			p4info_match = p4info_helper.get_match_field(
				table_name, match_field_name)
			match_type = p4info_match.match_type
			if match_type in match_types_with_priority:
				raise AssertionError(
					"non-zero 'priority' field is required for all entries for table {} in {}"
					.format(table_name, runtime_json)
				)


def runCommand(cli_path, thrift_port, command):
	p = subprocess.Popen([cli_path, '--thrift-port', str(thrift_port)], 
			stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	stdout, nosterr = p.communicate(input=bytes(command, 'UTF-8'))
	raw_results = stdout.split(b'RuntimeCmd:')[1:len(command)+1]
	final_results = raw_results[0].decode('UTF-8').split('\n')
	return final_results


def json_load_byteified(file_handle):
	return json.load(file_handle)


def _byteify(data, ignore_dicts=False):
	# if this is a unicode string, return its string representation
	if isinstance(data, str):
		return data.encode('utf-8')
	# if this is a list of values, return list of byteified values
	if isinstance(data, list):
		return [_byteify(item, ignore_dicts=True) for item in data]
	# if this is a dictionary, return dictionary of byteified keys and values
	# but only if we haven't already byteified it
	if isinstance(data, dict) and not ignore_dicts:
		return {
			_byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
			for key, value in data.items()
		}
	# if it's anything else, return it in its original form
	return data


def generate_table_add(flow):
	table_name = flow['table']
	action_name = flow['action_name']
	match_fields = ''
	if 'match' in flow: 
		for match_name in flow['match']:
			match_fields += str(flow['match'][match_name][0])
			match_fields += ' '
	action_params = ''
	for param_name in flow['action_params']:
		action_params += str(flow['action_params'][param_name])
		action_params += ' '
	
	if 'default_action' in flow and flow['default_action'] == True:
		return "table_set_default %s %s %s" % (
				table_name, action_name, action_params)
	return "table_add %s %s %s => %s" % (
			table_name, action_name, match_fields, action_params)


def generate_group_entry(rule):
	group_id = rule["multicast_group_id"]

	mgrp_command = "mc_mgrp_create " + str(group_id)

# This is assuming that every multicast group has exactly one node
	mcnd_command = "mc_node_create " + str(group_id) + " "

	for replica in rule['replicas']:
		mcnd_command += str(replica['egress_port'])
		mcnd_command += ' '
	
	return mgrp_command, mcnd_command

def generate_associate_cmd(rule, node_handle):
	ass_command = "mc_node_associate "
	group_id = rule['multicast_group_id']
	ass_command += str(group_id)
	ass_command += ' '
	ass_command += str(node_handle)

	return ass_command

if __name__ == '__main__':
	main()
