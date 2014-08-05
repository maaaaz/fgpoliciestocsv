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
option_1 = { 'name' : ('-o', '--output-file'), 'help' : '<OUTPUT_FILE>: output csv file (default \'./groups-out.csv\')', 'default' : 'groups-out.csv', 'nargs' : 1}
option_2 = { 'name' : ('-n', '--newline'), 'help' : '<NEWLINE> : insert a newline between each group for better readability', 'action' : 'store_true', 'default' : False }
option_3 = { 'name' : ('-s', '--skip-header'), 'help' : '<SKIP_HEADER> : do not print the csv header', 'action' : 'store_true', 'default' : False }

options = [option_0, option_1, option_2, option_3]

# Handful patterns
# -- Entering group definition block
p_entering_group_block = re.compile('^\s*config firewall addrgrp$', re.IGNORECASE)

# -- Exiting group definition block
p_exiting_group_block = re.compile('^end$', re.IGNORECASE)

# -- Commiting the current group definition and going to the next one
p_group_next = re.compile('^next$', re.IGNORECASE)

# -- Policy number
p_group_name = re.compile('^\s*edit\s+"(?P<group_name>.*)"$', re.IGNORECASE)

# -- Policy setting
p_group_set = re.compile('^\s*set\s+(?P<group_key>\S+)\s+(?P<group_value>.*)$', re.IGNORECASE)

# Functions
def parse(fd):
	"""
		Parse the data according to several regexes
		
		@param fd:	input file descriptor
		@rtype:	return a list of groups ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
				and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
	"""
	global p_entering_group_block, p_exiting_group_block, p_group_next, p_group_name, p_group_set
	
	in_group_block = False
	
	group_list = []
	group_elem = {}
	
	order_keys = []
	
	with open(fd,'rb') as fd_input:
		for line in fd_input:
			line = line.lstrip().rstrip().strip()
			
			# We match a group block
			if p_entering_group_block.search(line):
				in_group_block = True
			
			# We are in a group block
			if in_group_block:
				if p_group_name.search(line):
					group_name = p_group_name.search(line).group('group_name')
					group_elem['name'] = group_name
					if not('name' in order_keys): order_keys.append('name')
				
				# We match a setting
				if p_group_set.search(line):
					group_key = p_group_set.search(line).group('group_key')
					if not(group_key in order_keys): order_keys.append(group_key)
					
					group_value = p_group_set.search(line).group('group_value').strip()
					group_value = re.sub('["]', '', group_value)
					
					group_elem[group_key] = group_value
				
				# We are done with the current group id
				if p_group_next.search(line):
					group_list.append(group_elem)
					group_elem = {}
			
			# We are exiting the group block
			if p_exiting_group_block.search(line):
				in_group_block = False
	
	return (group_list, order_keys)


def generate_csv(results, keys, fd, newline, skip_header):
	"""
		Generate a plain ';' separated csv file

		@param fd : output file descriptor
	"""
	if results and keys:
		with open(fd,'wb') as fd_output:
			#spamwriter = csv.writer(fd_output, delimiter=';', quoting=csv.QUOTE_ALL)
			spamwriter = csv.writer(fd_output, delimiter=';')
			
			if not(skip_header):
				spamwriter.writerow(keys)
			
			for group in results:
				output_line = []
				
				for key in keys:
					if key in group.keys():
                                                if "member" == key:
                                                    output_line.append("\n".join(group[key].split(" ")))
                                                else:
                                                    output_line.append(group[key])
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
