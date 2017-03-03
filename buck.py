#!/usr/local/bin/python2.7
# encoding: utf-8

import sys
import os
import socket
import argparsewrapper

from argparsewrapper import ArgParseWrapper
from scapy.all import *

def scanHost(host, port_list, scan_flags):	
	#print("Scanning: %s" % host)
	
	#set up the IP packet
	ip = IP()
	ip.dst = host
	
	#ping host to make sure it is up, no point in starting a port scan if host is not up
	icmp = ICMP()
	packet = (ip/icmp)
	result = sr1(packet, timeout=3, verbose=False)
	if result is None:
		return -1, -1
	
	#if we're just doing a ping scan, we don't need to continue with the port scann
	if scan_flags['sn'] == True:
		return [], []

	open_ports = []
	filtered_ports = []

	#go through each port in the port list
	for p in port_list:
		#print("Scanning port: %d" % p)
		#the packet that will be either TCP or UDP
		port_packet = 0

		if scan_flags['u'] == True:
			port_packet = UDP()
		else:
			port_packet = TCP()
			#set the flags if we're doing a Christmas Tree scan
			if scan_flags['x'] == True:
				port_packet.flags = "UFP"

		#set the destination port to the current port
		port_packet.dport = p
		
		#put the IP and port scanning packets together and send it
		packet = (ip/port_packet)
		result = sr1(packet, timeout=3, verbose=False)
		
		#if we get no response, it's probably filtered
		if result is None:
			filtered_ports.append(p)
		else:
			#get the response flags
			#doing a UDP scan
			if scan_flags['u'] == True:
				#the port is open
				if result.haslayer(UDP) == True:
					open_ports.append(p)
				#the port is closed
				elif result.haslayer(ICMP) == True:
					continue
			#doing a TCP scan
			else:
				tcp_flags = result[TCP].flags
				#port is open for regular tcp
				if tcp_flags == 0x12:
					#we should be nice and send back a closing flag so the destination doesn't keep waiting
					port_packet.flags = 0x14
					packet = (ip/port_packet)
					sr1(packet, timeout=1, verbose=False)
					if p == 22:
						banner = get_ssh_banner(host, p)
						open_ports.append("22 - version: %s" % banner)
					else:
						open_ports.append(p)
				#port is open for xmas scan
				elif tcp_flags == 0x10 and scan_flags['x'] == True:
					open_ports.append(p)
					#we should be nice and send back a closing flag so the destination doesn't keep waiting
					port_packet.flags = 0x14
					packet = (ip/port_packet)
					sr1(packet, timeout=1, verbose=False)
					
	
	return open_ports, filtered_ports
	
def get_ssh_banner(host, port):
	try:
		soc = socket.socket()
		soc.connect((host,port))
		banner = soc.recv(1024)
	except:
		return -1

	return banner

def scan(host_list, port_list, scan_flags):
	
	if len(host_list) == 0:
		return {}
		
	rval_open = {}
	rval_filtered = {}
	
	#scan each host in our host list
	for h in host_list:
		open_ports, filtered_ports = scanHost(h, port_list, scan_flags)
		if open_ports == -1:
			continue
		else:
			rval_open[h] = open_ports
			rval_filtered[h] = filtered_ports
	
	return rval_open, rval_filtered

#export the results to an HTML file
def exportHTML(host_open_port_dictionary, host_filtered_port_dictionary, scan_flags):
	fname = (scan_flags['html'] + '.html')
	
	f = open(fname, 'w')
	f.write("<!doctype html>\n")
	f.write("<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	f.write("<title>Buckaneer Port Scan Report</title>\n</head>\n")
	 
	f.write("<body>\n")
	 
	for x in host_open_port_dictionary:
		f.write("<b>Host: %s</b><br>\n" % x)
		if host_open_port_dictionary[x] == -1:
			f.write("Host is unreachable.<br>\n")
		else:
			if scan_flags['sn'] == True:
				f.write("Host is up.<br>\n")
			else:
				f.write("Open ports:<br>\n")
				if len(host_open_port_dictionary[x]) == 0:
					f.write("None")
				else:
					f.write("<ul>\n")
					for p in host_open_port_dictionary[x]:
						f.write("<li>%s</li>\n" % str(p))
					f.write("</ul>\n")
				f.write("Filtered ports:<br>\n")
				if len(host_filtered_port_dictionary[x]) == 0:
					f.write("None")
				else:
					f.write("<ul>\n")
					for p in host_filtered_port_dictionary[x]:
						f.write("<li>%i</li>\n" % p)
					f.write("</ul>\n")
		f.write("<br>\n")

	f.write("</body>\n</html>")
	
	f.close()
	
	return

#export the results to the terminal
def exportCMD(host_open_port_dictionary, host_filtered_port_dictionary, scan_flags):
	if len(host_open_port_dictionary) == 0:
		print("No hosts scanned.")
		return
	
	print("---------------------Results---------------------")
	for x in host_open_port_dictionary:
		print("Host: %s" % x)
		if host_open_port_dictionary[x] == -1:
			print("\tHost is unreachable.")
		else:
			if scan_flags['sn'] == True:
				print("\tHost is up.")
			else:
				print("\tOpen ports:")
				if len(host_open_port_dictionary[x]) == 0:
					print("\t\tNone")
				else:
					for p in host_open_port_dictionary[x]:
						print("\t\t%s" % str(p))
				print("\tFiltered ports:")
				if len(host_filtered_port_dictionary[x]) == 0:
					print("\t\tNone")
				else:
					for p in host_filtered_port_dictionary[x]:
						print("\t\t%i" % p)
						  
def export(host_open_port_dictionary, host_filtered_port_dictionary, scan_flags):
	if scan_flags['html'] != None:
		exportHTML(host_open_port_dictionary, host_filtered_port_dictionary, scan_flags)
	else:
		exportCMD(host_open_port_dictionary, host_filtered_port_dictionary, scan_flags)

def main():

	parserWrapper = ArgParseWrapper()
	
	host_list, port_list, scan_flags = parserWrapper.parseArgs()

	host_open_port_dictionary, host_filtered_port_dictionary = scan(host_list, port_list, scan_flags)
	
	export(host_open_port_dictionary, host_filtered_port_dictionary, scan_flags)


if __name__== "__main__":
	main()
