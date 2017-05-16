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
option_1 = { 'name' : ('-o', '--output-file'), 'help' : '<OUTPUT_FILE>: output csv file (default \'./policies-out.csv\')', 'default' : 'policies-out.csv', 'nargs' : 1}
option_2 = { 'name' : ('-n', '--newline'), 'help' : '<NEWLINE> : insert a newline between each srvgroup for better readability', 'action' : 'store_true', 'default' : False }
option_3 = { 'name' : ('-s', '--skip-header'), 'help' : '<SKIP_HEADER> : do not print the csv header', 'action' : 'store_true', 'default' : False }
option_4 = { 'name' : ('-v', '--with-vdom'), 'help' : '<WITH_VDOM> : Config file contains VDOM', 'action' : 'store_true', 'default' : False }

options = [option_0, option_1, option_2, option_3, option_4]

# Handful patterns
# -- Entering address definition block
p_entering_vdom = re.compile('^\s*config vdom$', re.IGNORECASE)

# -- Entering srvgroup definition block
p_entering_srvgroup_block = re.compile('^\s*config firewall service group$', re.IGNORECASE)

# -- Exiting srvgroup definition block
p_exiting_srvgroup_block = re.compile('^end$', re.IGNORECASE)

# -- Commiting the current srvgroup definition and going to the next one
p_srvgroup_next = re.compile('^next$', re.IGNORECASE)

# -- srvgroup number
p_srvgroup_number = re.compile('^\s*edit\s+(?P<srvgroup_number>\d+)', re.IGNORECASE)

# -- srvgroup setting
p_srvgroup_set = re.compile('^\s*set\s+(?P<srvgroup_key>\S+)\s+(?P<srvgroup_value>.*)$', re.IGNORECASE)

# Functions
def parse(fd, with_vdom):
	"""
		Parse the data according to several regexes
		
		@param fd:	input file descriptor
		@rtype:	return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
				and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
	"""
	global p_entering_srvgroup_block, p_exiting_srvgroup_block, p_srvgroup_next, p_srvgroup_number, p_srvgroup_set, p_entering_vdom
	
	in_srvgroup_block = False
	in_vdom = False

	
	srvgroup_list = []
	srvgroup_elem = {}
	
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

			# We match a srvgroup block
			if p_entering_srvgroup_block.search(line):
				in_srvgroup_block = True
			
			# We are in a srvgroup block
			if in_srvgroup_block:
				# If config file contains vdom, add vdom name in front
				if with_vdom:
					srvgroup_elem['vdom'] = cur_vdom
					
				if p_srvgroup_number.search(line):
					srvgroup_number = p_srvgroup_number.search(line).group('srvgroup_number')
					srvgroup_elem['id'] = srvgroup_number
					if not('id' in order_keys): order_keys.append('id')
				
				# We match a setting
				if p_srvgroup_set.search(line):
					srvgroup_key = p_srvgroup_set.search(line).group('srvgroup_key')
					if not(srvgroup_key in order_keys): order_keys.append(srvgroup_key)
					
					srvgroup_value = p_srvgroup_set.search(line).group('srvgroup_value').strip()
					srvgroup_value = re.sub('["]', '', srvgroup_value)
					
					srvgroup_elem[srvgroup_key] = srvgroup_value
				
				# We are done with the current srvgroup id
				if p_srvgroup_next.search(line):
					srvgroup_list.append(srvgroup_elem)
					srvgroup_elem = {}
			
			# We are exiting the srvgroup block
			if p_exiting_srvgroup_block.search(line):
				in_srvgroup_block = False
	
	return (srvgroup_list, order_keys)


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
			
			for srvgroup in results:
				output_line = []
				
				for key in keys:
					if key in srvgroup.keys():
						output_line.append(srvgroup[key])
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
