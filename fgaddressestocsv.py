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
option_1 = { 'name' : ('-o', '--output-file'), 'help' : '<OUTPUT_FILE>: output csv file (default \'./addresses-out.csv\')', 'default' : 'addresses-out.csv', 'nargs' : 1}
option_2 = { 'name' : ('-n', '--newline'), 'help' : '<NEWLINE> : insert a newline between each address for better readability', 'action' : 'store_true', 'default' : False }
option_3 = { 'name' : ('-s', '--skip-header'), 'help' : '<SKIP_HEADER> : do not print the csv header', 'action' : 'store_true', 'default' : False }

options = [option_0, option_1, option_2, option_3]

# Handful patterns
# -- Entering address definition block
p_entering_address_block = re.compile('^\s*config firewall address$', re.IGNORECASE)

# -- Exiting address definition block
p_exiting_address_block = re.compile('^end$', re.IGNORECASE)

# -- Commiting the current address definition and going to the next one
p_address_next = re.compile('^next$', re.IGNORECASE)

# -- Policy number
p_address_name = re.compile('^\s*edit\s+"(?P<address_name>.*)"$', re.IGNORECASE)

# -- Policy setting
p_address_set = re.compile('^\s*set\s+(?P<address_key>\S+)\s+(?P<address_value>.*)$', re.IGNORECASE)

# Functions
def parse(fd):
	"""
		Parse the data according to several regexes
		
		@param fd:	input file descriptor
		@rtype:	return a list of addresses ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
				and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
	"""
	global p_entering_address_block, p_exiting_address_block, p_address_next, p_address_name, p_address_set
	
	in_address_block = False
	
	address_list = []
	address_elem = {}
	
	order_keys = []
	
	with open(fd,'rb') as fd_input:
		for line in fd_input:
			line = line.lstrip().rstrip().strip()
			
			# We match a address block
			if p_entering_address_block.search(line):
				in_address_block = True
			
			# We are in a address block
			if in_address_block:
				if p_address_name.search(line):
					address_name = p_address_name.search(line).group('address_name')
					address_elem['name'] = address_name
					if not('name' in order_keys): order_keys.append('name')
				
				# We match a setting
				if p_address_set.search(line):
					address_key = p_address_set.search(line).group('address_key')
					if not(address_key in order_keys): order_keys.append(address_key)
					
					address_value = p_address_set.search(line).group('address_value').strip()
					address_value = re.sub('["]', '', address_value)
					
					address_elem[address_key] = address_value
				
				# We are done with the current address id
				if p_address_next.search(line):
					address_list.append(address_elem)
					address_elem = {}
			
			# We are exiting the address block
			if p_exiting_address_block.search(line):
				in_address_block = False
	
	return (address_list, order_keys)


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
			
			for address in results:
				output_line = []
				
				for key in keys:
					if key in address.keys():
						output_line.append(address[key])
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
				
	results, keys = parse(options.input_file)
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
