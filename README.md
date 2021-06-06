fgpoliciestocsv
===============

Description
-----------
A collection of simple scripts to extract policies, groups, addresses and services from a FortiGate configuration file to CSV

Features
--------
The `fgpoliciestocsv` script extracts policies and comes in two languages : Perl and Python.  
The Python one was originally a simple port of the Perl one developped by Sebastian Knoop-Troullier aka `firewallguru` and published on his blog http://firewallguru.blogspot.fr/2014/04/exporting-firewall-rules-to-csv.html

Three other scripts `fggroupstocsv`, `fgaddressestocsv`, `fgservicestocsv` have been added to extract groups, addresses (IPv4 unicast only for now) and services ; and only come in Python.


Usage
-----
#### Python version  
Pass the configuration file to the scripts with the -i option.  
The processed output is available in the `policies-out.csv`, `addresses-out.csv`, `groups-out.csv`, `services-out.csv` (default) or in the specified file with the -o option.  

#### Perl version  
Pass the configuration file to the script this is the only supported argument.  
The processed output is available in the `policies-out.csv` file.  

### Options
#### Python
```
$ python fgpoliciestocsv.py -h
Usage: fgpoliciestocsv.py [options]

Options:
  -h, --help            show this help message and exit

  Main parameters:
    -i INPUT_FILE, --input-file=INPUT_FILE
                        Partial or full Fortigate configuration file. Ex:
                        fgfw.cfg
    -o OUTPUT_FILE, --output-file=OUTPUT_FILE
                        Output csv file (default ./policies-out.csv)
    -s, --skip-header   Do not print the csv header
    -n, --newline       Insert a newline between each policy for better
                        readability
    -d DELIMITER, --delimiter=DELIMITER
                        CSV delimiter (default ";")
    -e ENCODING, --encoding=ENCODING
                        Input file encoding (default "utf8")
```

#### Perl
```
$ perl fgpoliciestocsv.pl <configuration_file.cfg>
```
  
  
### Example
```
$ cat example.cfg
config firewall policy
     edit 1
         set srcintf "internal"
         set dstintf "wan1"
             set srcaddr "all"
             set dstaddr "all"
         set action accept
         set schedule "always"
             set service "ANY"
         set logtraffic-app disable
         set webcache enable
         set nat enable
     next
end

$ python fgpoliciestocsv.py -i example.cfg

$ cat policies-out.csv
id;srcintf;dstintf;srcaddr;dstaddr;action;schedule;service;logtraffic-app;webcache;nat
1;internal;wan1;all;all;accept;always;ANY;disable;enable;enable
```

Notes
-----
For a policy, an empty value in the `action` column might mean `deny`, as this is implicit in a FortiGate configuration file.

Requirements
------------
* Python >= 2.7
* Perl

Copyright and license
---------------------
fgpoliciestocsv is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
fgpoliciestocsv is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with fgpoliciestocsv. 
If not, see http://www.gnu.org/licenses/.

Fortinet holds every rights about the FortiGate brand. I'm not affiliated nor employed by them.

Credits
-------
* Sebastian Knoop-Troullier aka `firewallguru`
* Landry Minoza aka `hobgoblinsmaster`
* `AngelOfTerror`