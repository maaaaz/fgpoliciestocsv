#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of fgpoliciestocsv.
#
# Copyright (C) 2014, 2020, Thomas Debize <tdebize at mail.com>
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from os import path
import io
import sys
import re
import csv
import os

# OptionParser imports
from optparse import OptionParser
from optparse import OptionGroup

# Options definition
parser = OptionParser(usage="%prog [options]")

main_grp = OptionGroup(parser, 'Main parameters')
main_grp.add_option('-i', '--input-file', help='Partial or full Fortigate configuration file. Ex: fgfw.cfg')
main_grp.add_option('-o', '--output-file', help='Output csv file (default ./addresses-out.csv)', default=path.abspath(path.join(os.getcwd(), './addresses-out.csv')))
main_grp.add_option('-s', '--skip-header', help='Do not print the csv header', action='store_true', default=False)
main_grp.add_option('-n', '--newline', help='Insert a newline between each group for better readability', action='store_true', default=False)
main_grp.add_option('-d', '--delimiter', help='CSV delimiter (default ";")', default=';')
main_grp.add_option('-e', '--encoding', help='Input file encoding (default "utf8")', default='utf8')
parser.option_groups.extend([main_grp])

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'r'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Handful patterns
# -- Entering address definition block
p_entering_address_block = re.compile(r'^\s*config firewall address$', re.IGNORECASE)

# -- Exiting address definition block
p_exiting_address_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current address definition and going to the next one
p_address_next = re.compile(r'^next$', re.IGNORECASE)

# -- Policy number
p_address_name = re.compile(r'^\s*edit\s+"(?P<address_name>.*)"$', re.IGNORECASE)

# -- Policy setting
p_address_set = re.compile(r'^\s*set\s+(?P<address_key>\S+)\s+(?P<address_value>.*)$', re.IGNORECASE)

# Functions
def parse(options):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of addresses ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_address_block, p_exiting_address_block, p_address_next, p_address_name, p_address_set
    
    in_address_block = False
    
    address_list = []
    address_elem = {}
    
    order_keys = []
    
    with io.open(options.input_file, mode=fd_read_options, encoding=options.encoding) as fd_input:
        for line in fd_input:
            line = line.strip()
            
            # We match a address block
            if p_entering_address_block.search(line):
                in_address_block = True
            
            # We are in a address block
            if in_address_block:
                if p_address_name.search(line):
                    address_name = p_address_name.search(line).group('address_name')
                    address_elem['name'] = address_name
                    if not('name' in order_keys):
                        order_keys.append('name')
                
                # We match a setting
                if p_address_set.search(line):
                    address_key = p_address_set.search(line).group('address_key')
                    if not(address_key in order_keys):
                        order_keys.append(address_key)
                    
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


def generate_csv(results, keys, options):
    """
        Generate a plain csv file
    """
    if results and keys:
        with io.open(options.output_file, mode=fd_write_options) as fd_output:
            spamwriter = csv.writer(fd_output, delimiter=options.delimiter, quoting=csv.QUOTE_ALL, lineterminator='\n')
            
            if not(options.skip_header):
                spamwriter.writerow(keys)
            
            for address in results:
                output_line = []
                
                for key in keys:
                    if key in address.keys():
                        output_line.append(address[key])
                    else:
                        output_line.append('')
            
                spamwriter.writerow(output_line)
                if options.newline:
                    spamwriter.writerow('')
        
        fd_output.close()
    
    return None

def main():
    """
        Dat main
    """
    global parser
    
    options, arguments = parser.parse_args()
    
    if (options.input_file == None):
        parser.error('Please specify a valid input file')
                
    results, keys = parse(options)
    generate_csv(results, keys, options)
    
    return None

if __name__ == "__main__" :
    main()