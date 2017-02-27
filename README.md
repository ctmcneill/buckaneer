# buckaneer
Port scanner project for IT567.

INSTALL

1. Make sure the buck.py file and the argparserwrapper.py file are in the same folder.

RUN

Minimum usage:

buck.py -t [target IP(s)] -p [port(s)]

Full usage:

buck.py [-h] -p P -t T [-x] [-sn] [-u] [-html HTML]

OPTIONS EXPLAINED:

  -h, --help  Show this help message and exit.
  
  -p P        The port(s) to be scanned. Can be a single port, comma-separated (no spaces), or a range.
              
              Example 1: -p 22 ; only scans port 22.
              
              Example 2: -p 22,23,80; scans ports 22, 23, 80; NOTE: port list cannot have spaces in between the ports.
              
              Example 3: -p 22-80; scans ports 22 through 80.
              
              Example 4: -p 23-80,1054; combines examples 2 and 3.
              
  -t T        The target host(s) to be scanned. Can be an IP address, a range of IP addresses, or a .txt file containing a list of IP address.
  
  -x          Enable Christmas Tree scan (use UFP flags).
  
  -sn         Only do a ping scan.
  
  -u          Use UDP for port scanning.
  
  -html HTML  Exports the results to an HTML file with the specifed name.

