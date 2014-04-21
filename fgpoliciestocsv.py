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
option_2 = { 'name' : ('-n', '--newline'), 'help' : '<NEWLINE> : insert a newline between each policy for better readability', 'action' : 'store_true', 'default' : False }
option_3 = { 'name' : ('-s', '--skip-header'), 'help' : '<SKIP_HEADER> : do not print the csv header', 'action' : 'store_true', 'default' : False }

options = [option_0, option_1, option_2, option_3]

# Handful patterns
# -- Entering policy definition block
p_entering_policy_block = re.compile('^\s*config firewall policy$', re.IGNORECASE)

# -- Exiting policy definition block
p_exiting_policy_block = re.compile('^end$', re.IGNORECASE)

# -- Commiting the current policy definition and going to the next one
p_policy_next = re.compile('^next$', re.IGNORECASE)

# -- Policy number
p_policy_number = re.compile('^\s*edit\s+(?P<policy_number>\d+)', re.IGNORECASE)

# -- Policy setting
p_policy_set = re.compile('^\s*set\s+(?P<policy_key>\S+)\s+(?P<policy_value>.*)$', re.IGNORECASE)

# Functions
def parse(fd):
	"""
		Parse the data according to several regexes
		
		@param fd:	input file descriptor
		@rtype:	return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
				and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
	"""
	global p_entering_policy_block, p_exiting_policy_block, p_policy_next, p_policy_number, p_policy_set
	
	in_policy_block = False
	
	policy_list = []
	policy_elem = {}
	
	order_keys = []
	
	with open(fd,'rb') as fd_input:
		for line in fd_input:
			line = line.lstrip().rstrip().strip()
			
			# We match a policy block
			if p_entering_policy_block.search(line):
				in_policy_block = True
			
			# We are in a policy block
			if in_policy_block:
				if p_policy_number.search(line):
					policy_number = p_policy_number.search(line).group('policy_number')
					policy_elem['id'] = policy_number
					if not('id' in order_keys): order_keys.append('id')
				
				# We match a setting
				if p_policy_set.search(line):
					policy_key = p_policy_set.search(line).group('policy_key')
					if not(policy_key in order_keys): order_keys.append(policy_key)
					
					policy_value = p_policy_set.search(line).group('policy_value').strip()
					policy_value = re.sub('["]', '', policy_value)
					
					policy_elem[policy_key] = policy_value
				
				# We are done with the current policy id
				if p_policy_next.search(line):
					policy_list.append(policy_elem)
					policy_elem = {}
			
			# We are exiting the policy block
			if p_exiting_policy_block.search(line):
				in_policy_block = False
	
	return (policy_list, order_keys)


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
			
			for policy in results:
				output_line = []
				
				for key in keys:
					if key in policy.keys():
						output_line.append(policy[key])
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