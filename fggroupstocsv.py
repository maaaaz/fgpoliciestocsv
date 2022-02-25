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
main_grp.add_option('-o', '--output-file', help='Output csv file (default ./groups-out.csv)', default=path.abspath(path.join(os.getcwd(), './groups-out.csv')))
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
# -- Entering group definition block
p_entering_group_block = re.compile(r'^\s*config firewall addrgrp$', re.IGNORECASE)

# -- Exiting group definition block
p_exiting_group_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current group definition and going to the next one
p_group_next = re.compile(r'^next$', re.IGNORECASE)

# -- Policy number
p_group_name = re.compile(r'^\s*edit\s+"(?P<group_name>.*)"$', re.IGNORECASE)

# -- Policy setting
p_group_set = re.compile(r'^\s*set\s+(?P<group_key>\S+)\s+(?P<group_value>.*)$', re.IGNORECASE)

# Functions
def parse(options):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of groups ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_group_block, p_exiting_group_block, p_group_next, p_group_name, p_group_set
    
    in_group_block = False
    
    group_list = []
    group_elem = {}
    
    order_keys = []
    
    with io.open(options.input_file, mode=fd_read_options, encoding=options.encoding) as fd_input:
        for line in fd_input:
            line = line.strip()
            
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


def generate_csv(results, keys, options):
    """
        Generate a plain ';' separated csv file
    """
    if results and keys:
        with io.open(options.output_file, mode=fd_write_options,encoding="UTF-8") as fd_output:
            spamwriter = csv.writer(fd_output, delimiter=options.delimiter, quoting=csv.QUOTE_ALL, lineterminator='\n')
            
            if not(options.skip_header):
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
