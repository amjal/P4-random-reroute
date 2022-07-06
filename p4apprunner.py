#!/usr/bin/python3
# Copyright 2013-present Barefoot Networks, Inc.
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

from __future__ import print_function

import argparse
from collections import OrderedDict
import json
import os
import sys
import tarfile

parser = argparse.ArgumentParser(description='p4apprunner')
parser.add_argument('--build-dir', help='Directory to build in.',
					type=str, action='store', required=False, default='./build')
parser.add_argument('--quiet', help='Suppress log messages.',
					action='store_true', required=False, default=False)
parser.add_argument('--build-only', help='Compile the program, but do not run it.',
					action='store_true', required=False, default=False)
parser.add_argument('--json', help='Use this compiled JSON file instead of compiling.',
					type=str, action='store', required=False, default=None)
parser.add_argument('--manifest', help='Path to manifest file.',
					type=str, action='store', required=False, default='./p4app.json')
parser.add_argument('app', help='.p4app package to run.', type=str)
parser.add_argument('target', help=('Target to run. Defaults to the first target '
									'in the package.'),
					nargs='?', type=str)

args = parser.parse_args()

def log(*items):
	if args.quiet != True:
		print(*items)

def log_error(*items):
	print(*items, file=sys.stderr)

def run_command(command):
	log('>', command)
	return os.WEXITSTATUS(os.system(command))

class Manifest:
	def __init__(self, program_file, language, target, target_config):
		self.program_file = program_file
		self.language = language
		self.target = target
		self.target_config = target_config

def read_manifest(manifest_file):
	manifest = json.load(manifest_file, object_pairs_hook=OrderedDict)

	if 'program' not in manifest:
		log_error('No program defined in manifest.')
		sys.exit(1)
	program_file = manifest['program']

	if 'language' not in manifest:
		log_error('No language defined in manifest.')
		sys.exit(1)
	language = manifest['language']

	if 'targets' not in manifest or len(manifest['targets']) < 1:
		log_error('No targets defined in manifest.')
		sys.exit(1)

	if args.target is not None:
		chosen_target = args.target
	elif 'default-target' in manifest:
		chosen_target = manifest['default-target']
	else:
		chosen_target = list(manifest['targets'].keys())[0]

	if chosen_target not in manifest['targets']:
		log_error('Target not found in manifest:', chosen_target)
		sys.exit(1)

	return Manifest(program_file, language, chosen_target, manifest['targets'][chosen_target])

def get_program_name(program_file):
	return os.path.basename(program_file).rstrip('.p4')

def create_format_dirs():
	if args.build_dir[-1] != '/':
		args.build_dir += '/'

	if not os.path.exists(args.build_dir): 
		log('Build dir does not exists... creating dir')
		os.mkdir(args.build_dir)

def run_compile_bmv2(manifest):

	if 'run-before-compile' in manifest.target_config:
		commands = manifest.target_config['run-before-compile']
		if not isinstance(commands, list):
			log_error('run-before-compile should be a list:', commands)
			sys.exit(1)
		for command in commands:
			run_command(command)

	compiler_args = []

	if manifest.language == 'p4-14':
		compiler_args.append('--p4v 14')
	elif manifest.language == 'p4-16':
		compiler_args.append('--p4v 16')
	else:
		log_error('Unknown language:', manifest.language)
		sys.exit(1)

	if 'compiler-flags' in manifest.target_config:
		flags = manifest.target_config['compiler-flags']
		if not isinstance(flags, list):
			log_error('compiler-flags should be a list:', flags)
			sys.exit(1)
		compiler_args.extend(flags)

	# Compile the program.
	output_file = args.build_dir + get_program_name(manifest.program_file) + '.json'
	compiler_args.append('"%s"' % manifest.program_file)
	compiler_args.append('-o "%s"' % output_file)
	runtime_file = args.build_dir + get_program_name(manifest.program_file) + '.p4.p4info.txt'
	compiler_args.append('--p4runtime-files "%s"' % runtime_file)
	rv = run_command('p4c-bm2-ss %s' % ' '.join(compiler_args))

	if 'run-after-compile' in manifest.target_config:
		commands = manifest.target_config['run-after-compile']
		if not isinstance(commands, list):
			log_error('run-after-compile should be a list:', commands)
			sys.exit(1)
		for command in commands:
			run_command(command)

	if rv != 0:
		log_error('Compile failed.')
		sys.exit(1)

	return output_file

def build_only(manifest):

	model = 'bmv2'
	if 'model' in manifest.target_config:
		model = manifest.target_config['model']

	if model == 'bmv2':
		output_file = run_compile_bmv2(manifest)
	else:
		log_error('Unrecognized model:', model)
		sys.exit(1)

	rc = run_command('cp %s /tmp/p4app_logs/program.json' % output_file)

	if rc != 0:
		log_error("Failed to copy compiled program to output location")
		sys.exit(1)

def run_stf(manifest):
	output_file = run_compile_bmv2(manifest)

	if not 'test' in manifest.target_config:
		log_error('No STF test file provided.')
		sys.exit(1)
	stf_file = manifest.target_config['test']

	# Run the program using the BMV2 STF interpreter.
	stf_args = []
	stf_args.append('-v')
	stf_args.append(os.path.join(args.build_dir, output_file))
	stf_args.append(os.path.join(args.build_dir, stf_file))

	program = '"%s/stf/bmv2stf.py"' % sys.path[0]
	rv = run_command('python2 %s %s' % (program, ' '.join(stf_args)))
	if rv != 0:
		sys.exit(1)
	return rv

def run_custom(manifest):
	output_file = run_compile_bmv2(manifest)
	script_args = []
	script_args.append('--behavioral-exe "%s"' % 'simple_switch')
	script_args.append('--json "%s"' % output_file)
	script_args.append('--cli "%s"' % 'simple_switch_CLI')
	if not 'program' in manifest.target_config:
		 log_error('No mininet program file provided.')
		 sys.exit(1)
	program = manifest.target_config['program']
	rv = run_command('python3 %s %s' % (program, ' '.join(script_args)))

	if rv != 0:
		sys.exit(1)
	return rv

def main():
	create_format_dirs()

	log('Reading package manifest.')
	with open(args.manifest, 'r') as manifest_file:
		manifest = read_manifest(manifest_file)

	# Dispatch to the backend implementation for this target.
	backend = manifest.target
	if 'use' in manifest.target_config:
		backend = manifest.target_config['use']

	if args.build_only or backend == 'compile-bmv2':
		build_only(manifest)
		rc = 0
	elif backend == 'stf':
		rc = run_stf(manifest)
	elif backend == 'custom':
		rc = run_custom(manifest)
	else:
		log_error('Target specifies unknown backend:', backend)
		sys.exit(1)

	sys.exit(rc)

if __name__ == '__main__':
	main()
