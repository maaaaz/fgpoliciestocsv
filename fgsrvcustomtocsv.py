#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fgpoliciestocsv.
#
# Copyright (C) 2014, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# fgpoliciestocsv is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fgpoliciestocsv is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with fgpoliciestocsv.  If not, see <http://www.gnu.org/licenses/>.

import re
import os
import sys
import csv

# OptionParser imports
from optparse import OptionParser

# Options definition
option_0 = { 'name' : ('-i', '--input-file'), 'help' : '<INPUT_FILE>: Fortigate configuration file. Ex: fgfw.cfg', 'nargs' : 1}
option_1 = { 'name' : ('-o', '--output-file'), 'help' : '<OUTPUT_FILE>: output csv file (default \'./srvcustom-out.csv\')', 'default' : 'policies-out.csv', 'nargs' : 1}
option_2 = { 'name' : ('-n', '--newline'), 'help' : '<NEWLINE> : insert a newline between each service for better readability', 'action' : 'store_true', 'default' : False }
option_3 = { 'name' : ('-s', '--skip-header'), 'help' : '<SKIP_HEADER> : do not print the csv header', 'action' : 'store_true', 'default' : False }
option_4 = { 'name' : ('-v', '--with-vdom'), 'help' : '<WITH_VDOM> : Config file contains VDOM', 'action' : 'store_true', 'default' : False }

options = [option_0, option_1, option_2, option_3, option_4]

# Handful patterns
# -- Entering address definition block
p_entering_vdom = re.compile('^\s*config vdom$', re.IGNORECASE)

# -- Entering service definition block
p_entering_service_block = re.compile('^\s*config firewall service custom$', re.IGNORECASE)

# -- Exiting service definition block
p_exiting_service_block = re.compile('^end$', re.IGNORECASE)

# -- Commiting the current service definition and going to the next one
p_service_next = re.compile('^next$', re.IGNORECASE)

# -- service number
p_service_number = re.compile('^\s*edit\s+(?P<service_number>\d+)', re.IGNORECASE)

# -- service setting
p_service_set = re.compile('^\s*set\s+(?P<service_key>\S+)\s+(?P<service_value>.*)$', re.IGNORECASE)

# Functions
def parse(fd, with_vdom):
	"""
		Parse the data according to several regexes
		
		@param fd:	input file descriptor
		@rtype:	return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
				and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
	"""
	global p_entering_service_block, p_exiting_service_block, p_service_next, p_service_number, p_service_set, p_entering_vdom
	
	in_service_block = False
	in_vdom = False

	
	service_list = []
	service_elem = {}
	
	order_keys = []
	
	with open(fd,'rb') as fd_input:
		for line in fd_input:
			line = line.lstrip().rstrip().strip()
			
			# Config_file contains vdom
			if with_vdom:
				# extract vdom name
				if in_vdom:
					cur_vdom = line.split (' ')[1]
					if not('vdom' in order_keys): order_keys.append('vdom')
					in_vdom = False
	
				# We match a vdom start
				if p_entering_vdom.search(line):
					in_vdom = True

			# We match a service block
			if p_entering_service_block.search(line):
				in_service_block = True
			
			# We are in a service block
			if in_service_block:
				# If config file contains vdom, add vdom name in front
				if with_vdom:
					service_elem['vdom'] = cur_vdom
					
				if p_service_number.search(line):
					service_number = p_service_number.search(line).group('service_number')
					service_elem['id'] = service_number
					if not('id' in order_keys): order_keys.append('id')
				
				# We match a setting
				if p_service_set.search(line):
					service_key = p_service_set.search(line).group('service_key')
					if not(service_key in order_keys): order_keys.append(service_key)
					
					service_value = p_service_set.search(line).group('service_value').strip()
					service_value = re.sub('["]', '', service_value)
					
					service_elem[service_key] = service_value
				
				# We are done with the current service id
				if p_service_next.search(line):
					service_list.append(service_elem)
					service_elem = {}
			
			# We are exiting the service block
			if p_exiting_service_block.search(line):
				in_service_block = False
	
	return (service_list, order_keys)


def generate_csv(results, keys, fd, newline, skip_header):
	"""
		Generate a plain ';' separated csv file

		@param fd : output file descriptor
	"""
	if results and keys:
		with open(fd,'wb') as fd_output:
			spamwriter = csv.writer(fd_output, delimiter=';')
			
			if not(skip_header):
				spamwriter.writerow(keys)
			
			for service in results:
				output_line = []
				
				for key in keys:
					if key in service.keys():
						output_line.append(service[key])
					else:
						output_line.append('')
			
				spamwriter.writerow(output_line)
				if newline: spamwriter.writerow('')		
		
		fd_output.close()
	
	return

def main(options, arguments):
	"""
		Dat main
	"""
	if (options.input_file == None):
		parser.error('Please specify a valid input file')
				
	results, keys = parse(options.input_file, options.with_vdom)
	generate_csv(results, keys, options.output_file, options.newline, options.skip_header)
	
	return
	

if __name__ == "__main__" :
	parser = OptionParser()
	for option in options:
		param = option['name']
		del option['name']
		parser.add_option(*param, **option)

	options, arguments = parser.parse_args()
	main(options, arguments)
