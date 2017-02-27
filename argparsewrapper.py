#!/usr/local/bin/python2.7
# encoding: utf-8

import socket
import argparse

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

PORT_REQUIRED_ERROR = "-p flag is required."
INVALID_PORT_RANGE_ERROR = "Port range invalid."
HOST_REQUIRED_ERROR = "--host flag is required."
PORT_ERROR = "Port value(s) invalid. Use -h option for help."
IP_ERROR = "Host address value(s) invalid. Use -h option for help."
FILE_ERROR  = "File could not be opened."
NO_HOSTS_ERROR = "No valid host IP addresses were found."
INVALID_HOST_RANGE_ERROR = "Host range invalid."

class ArgParseWrapper:

	parser = 0

	def __init__(self):
		self.parser = 0

	#checks if the input is a valid port number
	def isValidPort(self, num):
		try:
			num = int(num)
		except:
			return False
		
		if not isinstance(num, int):
			return False
		
		if (num < 1) or (num > 65535):
			return False
		
		return True

	def parsePortRange(self, port_range):
		rval = []

		port_range = port_range.split('-')
		try:
			start_port = int(port_range[0])
			end_port = int(port_range[1])
		except:
			self.parser.error(PORT_ERROR)

		if not (start_port < end_port):
			self.parser.error(INVALID_PORT_RANGE_ERROR)

		for x in range(start_port, (end_port+1)):
			if self.isValidPort(x) == True:
				rval.append(x)
			else:
				self.parser.error(PORT_ERROR)

		return rval

	def parsePortList(self, ports):
		rval = []

		ports = ports.split(',')
		for current_token in ports:
			#check if the current token contains a range
			if '-' in current_token:
				port_list = self.parsePortRange(current_token)

				for x in port_list:
					rval.append(x)
			#current toekn is just one port
			else:
				if self.isValidPort(current_token) == True:
					current_token = int(current_token)
					rval.append(current_token)
				else:
					self.parser.error(PORT_ERROR)

		return rval


	#parses the input into a list of ports to be scanned
	def parsePorts(self, ports):
		rval = []
		
		#check to see if input is a list
		if "," in ports:
			rval = self.parsePortList(ports)
					
		#check to see if input is just one range
		elif "-" in ports:
			port_list = self.parsePortRange(ports)

			for x in port_list:
				rval.append(x)
		
		#input must be a single port
		else:
			if self.isValidPort(ports) == True:
				rval.append(int(ports))
			else:
				self.parser.error(PORT_ERROR)
		
		return rval

	#check if the input is a valid IP address
	def isValidIPAddress(self, ip):
		try:
			socket.inet_aton(ip)
		except socket.error:
			return False
		
		return True
		
	def readHostsFromFile(self, fname):
		rval = []
		
		try:
			f = open(fname, 'r')
		except:
			self.parser.error(FILE_ERROR)
		
		for line in f:
			line = line.strip()
			if self.isValidIPAddress(line) == True:
				rval.append(line)
				
		f.close()
		
		return rval
				
	def parseHostRange(self, hosts):
		rval = []

		host_range = hosts.split('-')
		start_ip = host_range[0]
		end_ip = host_range[1]

		try:
			end_ip = int(end_ip)
		except:
			self.parser.error(INVALID_HOST_RANGE_ERROR)

		ip_octet_list = start_ip.split('.')
		
		if len(ip_octet_list) != 4:
			self.parser.error(INVALID_HOST_RANGE_ERROR)

		for x in range (int(ip_octet_list[3]), (end_ip+1)):
			current_ip = ip_octet_list[0] + '.' + ip_octet_list[1] + '.' + ip_octet_list[2] + '.' + str(x)

			if not self.isValidIPAddress(current_ip):
				parser.error(INVALID_HOST_RANGE_ERROR)

			rval.append(current_ip)

		return rval

	#parses input into a list of hosts to be scanned
	def parseHosts(self, hosts):
		rval = []
		
		#check if hosts is a file
		if ".txt" in hosts:
			rval = self.readHostsFromFile(hosts)
			return rval
		
		#check for range
		elif "-" in hosts:
			rval = self.parseHostRange(hosts)
		
		#check for subnet mask
		elif "/" in hosts:
			self.parser.error("Subnet masks not supported at this time. Sorry.")
		
		#must be a single IP address
		elif self.isValidIPAddress(hosts) == True:
			rval.append(hosts)
		else:
			self.parser.error(IP_ERROR)
		
		return rval

	#parses the command line arguments
	def parseArgs(self):
		#staring up the parser
		self.parser = argparse.ArgumentParser(description='Buckeener port scanner by Chris McNeill. It\'s called \"Buckeneer\" because it raids ports.')
		
		#--------available arguments----------
		
		#-p flag: ports follow, required arg
		self.parser.add_argument('-p', help='The port(s) to be scanned. Can be a single port, comma-separated (no spaces), or a range. Example 1: -p 22; Example 2: -p 22,23,80; Example 3: -p 22-80; Example 4: -p 23-80,1054', required=True)
		
		#-t flag: targets (as IP addresses) follow, required arg
		self.parser.add_argument('-t', help='The target host(s) to be scanned. Can be an IP address, a range of IP addresses, or a .txt file containing a list of IP address', required=True)
		
		#-x flag: when present, do a Christmas Tree scan
		self.parser.add_argument('-x', help='Enable Christmas Tree scan (use all TCP flags)', action='store_true')
		
		#-sn flag: when present, just do a ping scan
		self.parser.add_argument('-sn', help='Only do a ping scan', action='store_true')

		#-u flag: when present, use UDP for the port scan
		self.parser.add_argument('-u', help='Use UDP for port scanning', action='store_true')

		#-html flag: when present, exports the output to an HTML file with the specified name
		self.parser.add_argument('-html', help='Exports the results to an HTML file with the specifed name')
		
		args = self.parser.parse_args()
		
		#getting optional flags
		ping = args.sn	
		xmas = args.x
		udp = args.u
		html = args.html
		
		#if we're just doign a ping scan, no need to parse ports
		if ping == True:
			port_list = []
		else:
			port_list = self.parsePorts(args.p)
			#remove duplicate port numbers
			port_list = list(set(port_list))

		if xmas == True and udp == True:
			self.parser.error("Can't do an Christmas tree scan and a UDP scan. That just doesn't make sense.")
			
		host_list = self.parseHosts(args.t)

		if len(host_list) == 0:
			self.parser.error(NO_HOSTS_ERROR)
		
		scan_flags = {'sn': ping, 'x': xmas, 'html': html, 'u': udp}
		
		return host_list, port_list, scan_flags
