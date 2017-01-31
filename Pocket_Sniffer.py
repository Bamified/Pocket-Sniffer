#!/usr/bin/python
"""	Barebones packet sniffer created in/for Linux
	Can't be used in Windows, because SOCK_RAW is disabled (line 136)
	
	Created by: Bart Frijters"""

import socket
import os
import struct
import binascii

#https://tools.ietf.org/html/rfc793
def analyze_tcp_header(data):
	tcp_hdr 	= struct.unpack("!2H2I4H" , data[:20])
	src_port 	= tcp_hdr[0]
	dst_port 	= tcp_hdr[1]
	seq_num 	= tcp_hdr[2]
	ack_num 	= tcp_hdr[3]
	data_offset = tcp_hdr[4] >> 12
	reserved 	= (tcp_hdr[4] >> 6) & 0x03ff #Must be zero (0000 0011 1111 1111)
	flags 		= tcp_hdr[4] & 0x003f #0000 0000 0011 1111
	urg 		= flags & 0x0020
	ack 		= flags & 0x0010
	psh 		= flags & 0x0008
	rst 		= flags & 0x0004
	syn 		= flags & 0x0002
	fin 		= flags & 0x0001
	window 		= tcp_hdr[5]
	checksum 	= tcp_hdr[6]
	urgent_ptr 	= tcp_hdr[7]
	
	print "--------------TCP HEADER---------------"
	print "\tSource:\t\t%hu" % src_port
	print "\tDestination:\t%hu" % dst_port
	print "\tSeq:\t\t%u" % seq_num
	print "\tAck:\t\t%u" % ack_num
	print "\tFlags:"
	print "\tURG\t\t%d" % urg
	print "\tACK\t\t%d" % ack
	print "\tPSH\t\t%d" % psh
	print "\tRST\t\t%d" % rst
	print "\tSYN\t\t%d" % syn
	print "\tFIN\t\t%d" % fin
	print "\tWindow Size:\t%hu" % window
	print "\tChecksum:\t%hu" % checksum	
	
	data = data[20:]
	return data

#https://tools.ietf.org/html/rfc768
def analyze_udp_header(data):
	udp_hdr = struct.unpack("!4H", data[:8])
	src_port = udp_hdr[0]
	des_port = udp_hdr[1]
	length = udp_hdr[2]
	checksum = udp_hdr[3]
	
	print "--------------UDP HEADER---------------"
	print "\tSource:\t%uh" % src_port
	print "\tDestination:\t%uh" % des_port
	print "\tLength:\t%uh" % length
	print "\tChecksum:\t%uh" % checksum
	
	data = data[8:]
	return data

#https://tools.ietf.org/html/rfc791
def analyze_ip_header(data):
	ip_hdr = struct.unpack("!6H4s4s" , data [:20])
	version = ip_hdr[0] >> 12 			#version
	ihl 	= (ip_hdr[0] >> 8) & 0x0f 	#Internet Header Length
	tos		= ip_hdr[0] & 0x00ff 		#Types of Service
	tot_len = ip_hdr[1] 				#total length
	ip_id	= ip_hdr[2] 				#Identification
	flags 	= ip_hdr[3] >> 13 			#flags (first 3 bits)
	offset 	= ip_hdr[3] & 0x1fff 		#fragment offset (ignore first 3 bits)
	ttl 	= ip_hdr[4] >> 8			#Time to Live
	ip_pro	= ip_hdr[4] & 0x00ff		#Protocol
	ch_sum	= ip_hdr[5]					#Header checksum
	src_add = socket.inet_ntoa(ip_hdr[6])	#Source address
	des_add = socket.inet_ntoa(ip_hdr[7])	#Destination address
	
	no_frag = flags >> 1
	more_frag = flags & 0x1
	
	print "--------------IP HEADER---------------"
	print "\tVersion:\t%hu" % version
	print "\tIHL:\t\t%hu" % ihl
	print "\tTOS:\t\t%hu" % tos
	print "\tTotal Length:\t%hu" % tot_len
	print "\tIdentification:\t%hu" % ip_id
	print "\tFlags:\t\t%hu" % flags
	print "\tNo Frag:\t%hu" % no_frag
	print "\tMore Frag:\t%hu" % more_frag
	print "\tOffset:\t\t%hu" % offset
	print "\tTime to Live:\t%hu" % ttl
	print "\tProtocol:\t%hu" % ip_pro
	print "\tChecksum:\t%hu" % ch_sum
	print "\tSource:\t\t%s" % src_add
	print "\tDestination:\t%s" % des_add
	
	if ip_pro == 6: #TCP
		next_proto = "TCP"
	elif ip_pro == 17: #UDP
		next_proto = "UDP"
	else:
		next_proto = "OTHER"
	
	data = data[20:]
	return data, next_proto

#https://en.wikipedia.org/wiki/Ethernet_frame#Structure
def analyze_ethernet_header(data):
	ip_boolean = False
	
	#data[:14] -> 6 + 6 + 2 bytes
	eth_hdr = struct.unpack("!6s6sH" , data[:14]) #IPv4 = 0x0000
	mac_dest 	= binascii.hexlify(eth_hdr[0]) 	#Destination MAC
	mac_src 	= binascii.hexlify(eth_hdr[1])	#Source MAC
	protocol 	= eth_hdr[2] >> 8	#Next protocol
	
	print "--------------ETH HEADER---------------"
	print "Destination MAC: %s:%s:%s:%s:%s:%s" % (mac_dest[0:2], 
	mac_dest[2:4], mac_dest[4:6], mac_dest[6:8], mac_dest[8:10], mac_dest[10:12])
	print "Source MAC: %s:%s:%s:%s:%s:%s" % (mac_src[0:2], 
	mac_src[2:4], mac_src[4:6], mac_src[6:8], mac_src[8:10], mac_src[10:12])
	print "Protocol: %s" % protocol
	
	if protocol == 0x08: #IPv4
		ip_boolean = True
	
	data = data[14:] #cut header out
	return data, ip_boolean
	
def main():
	sn_socket = socket.socket(socket.PF_PACKET , socket.SOCK_RAW , socket.htons(0x0003))
	recv_data = sn_socket.recv(2048)
	os.system("clear")
	
	data, ip_boolean = analyze_ethernet_header(recv_data)
	
	if ip_boolean:
		data, next_proto = analyze_ip_header(data)
	else:
		return	
	
	if next_proto == "TCP":
		data = analyze_tcp_header(data)
	elif next_proto == "UDP":
		data = analyze_udp_header(data)
	else:
		return

while True:	
	main()
