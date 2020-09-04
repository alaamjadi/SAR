from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
import collections
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
from collections import deque


# Packet Classification parameters
SRC_IP = 0
DST_IP = 1
PROTO  = 2
SPORT  = 3
DPORT  = 4
ACTION = 5

# IP lookup parameters
IP     = 0
SUBNET = 1
DPID   = 2	#commented

# Topologies
TOPO = 2


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}
	
	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.no_of_nodes = 0
		self.no_of_links = 0		
		self.datapaths = []
		self.switch_id = []
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.i=0
		
		# Packet Classification initial parameters
		
		self.classify = {}
		self.classify["r1"] = ["195.0.0.1","128.128.0.1","6","1234","1234","allow"]
		self.classify["r2"] = ["128.128.0.1","195.0.0.1","6","123","*","allow"]
		self.classify["r3"] = ["197.0.0.1","128.128.0.1","1","*","123","allow"]
		self.classify["r4"] = ["128.128.0.1","197.0.0.1","1","*","*","allow"]
		#self.classify["r5"] = ["*","*","*","*","*","deny"]
 
		self.counters = {} 
		self.counters["r1"] = 0                           
		self.counters["r2"] = 0                           
		self.counters["r3"] = 0                           
		self.counters["r4"] = 0                           
		#self.counters["r5"] = 0       
		
		if TOPO == 1:			
			self.switch = {}
			self.switch["195.0.0.254"  ] = ["195.0.0.254","8","1"] 
			self.switch["128.128.0.254"] = ["128.128.0.254","12","2"] 
			self.switch["154.128.0.254"] = ["154.128.0.254","16","3"] 

			self.lookup = {}
			self.lookup["195.0.0.1"]   = "195.0.0.254"
			self.lookup["195.0.0.2"]   = "195.0.0.254"
			self.lookup["128.128.0.1"] = "128.128.0.254"
			self.lookup["128.128.0.2"] = "128.128.0.254"
			self.lookup["154.128.0.1"] = "154.128.0.254"
			self.lookup["154.128.0.2"] = "154.128.0.254"
			
			self.ip_to_mac = {}
			self.ip_to_mac["195.0.0.1"]   = "00:00:00:00:00:01"
			self.ip_to_mac["195.0.0.2"]   = "00:00:00:00:00:02"
			self.ip_to_mac["128.128.0.1"] = "00:00:00:00:00:03"
			self.ip_to_mac["128.128.0.2"] = "00:00:00:00:00:04"
			self.ip_to_mac["154.128.0.1"] = "00:00:00:00:00:05"
			self.ip_to_mac["154.128.0.2"] = "00:00:00:00:00:06"
		
		elif TOPO == 2:
			self.switch = {}
			self.switch["195.0.0.254"  ]   = ["195.0.0.254","8","1"] 
			self.switch["128.128.0.254"]   = ["128.128.0.254","12","2"] 
			self.switch["154.128.0.254"]   = ["154.128.0.254","16","3"] 
			self.switch["197.160.0.254"]   = ["197.160.0.254","24","4"]
			self.switch["192.168.0.254"]   = ["192.168.0.254","24","5"]	
			self.switch["192.169.0.254"]  = ["192.169.0.254","24","6"]
			self.switch["192.170.0.254"]  = ["192.170.0.254","24","7"]

			self.lookup = {}
			self.lookup["195.0.0.1"]     = "195.0.0.254"
			self.lookup["195.0.0.2"]     = "195.0.0.254"
			self.lookup["128.128.0.1"]   = "128.128.0.254"
			self.lookup["154.128.0.1"]   = "154.128.0.254"
			self.lookup["197.160.0.1"]   = "197.160.0.254"
			self.lookup["192.168.0.1"]   = "192.168.0.254"
			self.lookup["192.169.0.1"]  = "192.169.0.254"
			self.lookup["192.170.0.1"]  = "192.170.0.254"

			
			self.ip_to_mac = {}
			self.ip_to_mac["195.0.0.1"]     = "00:00:00:00:00:01"
			self.ip_to_mac["195.0.0.2"]     = "00:00:00:00:00:02"
			self.ip_to_mac["128.128.0.1"]   = "00:00:00:00:00:03"
			self.ip_to_mac["154.128.0.1"]   = "00:00:00:00:00:04"
			self.ip_to_mac["197.160.0.1"]   = "00:00:00:00:00:05"
			self.ip_to_mac["192.168.0.1"]   = "00:00:00:00:00:06"
			self.ip_to_mac["192.169.0.1"]  = "00:00:00:00:00:07"
			self.ip_to_mac["192.170.0.1"]  = "00:00:00:00:00:08"			

	
		
		
	def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
		if opcode == 1:
			targetMac = "00:00:00:00:00:00"
			targetIp = dstIp
		elif opcode == 2:
			targetMac = dstMac
			targetIp = dstIp

		e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()

		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath,
			buffer_id=0xffffffff,
			in_port=datapath.ofproto.OFPP_CONTROLLER,
			actions=actions,
			data=p.data)
		datapath.send_msg(out)

		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		msg = ev.msg
		self.datapaths.append(msg.datapath)
		self.switch_id.append(msg.datapath_id)
		
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
		
	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
        
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']		

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
			return
		dst = eth.dst
		src = eth.src
		
		dpid_src = datapath.id
		
		# TOPOLOGY DISCOVERY------------------------------------------
		
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]		
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		# print links
		
		# MAC LEARNING-------------------------------------------------
		
		self.mac_to_port.setdefault(dpid_src, {})
		self.mac_to_port.setdefault(src, {})
		self.port_to_mac.setdefault(dpid_src, {})
		self.mac_to_port[dpid_src][src] = in_port	
		self.mac_to_dpid[src] = dpid_src
		self.port_to_mac[dpid_src][in_port] = src
		self.logger.info("Packet in the controller from switch: %s", dpid_src)
		#print self.mac_to_port
		
		# HANDLE ARP PACKETS--------------------------------------------
		
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_packet = pkt.get_protocol(arp.arp)
			arp_dst_ip = arp_packet.dst_ip
			arp_src_ip = arp_packet.src_ip
			# self.logger.info("ARP packet from switch: %s source IP: %s destination IP: %s from port: %s", dpid_src, arp_src_ip, arp_dst_ip, in_port)
			# self.logger.info("ARP packet from switch: %s source MAC: %s destination MAC:%s from port: %s", dpid_src, src, dst, in_port)
			
			if arp_dst_ip in self.ip_to_mac:
				if arp_packet.opcode == 1:
					# send arp reply (SAME SUBNET)
					dstIp = arp_src_ip
					srcIp = arp_dst_ip
					dstMac = src
					srcMac = self.ip_to_mac[arp_dst_ip]
					outPort = in_port
					opcode = 2 # arp reply packet
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
			else:
				if arp_packet.opcode == 1:
					# send arp reply (GATEWAY)
					dstIp = arp_src_ip
					srcIp = arp_dst_ip
					dstMac = src
					srcMac = self.port_to_mac[dpid_src][in_port]
					outPort = in_port
					opcode = 2 # arp reply packet
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
		
		# HANDLE IP PACKETS----------------------------------------------- 	
		
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:
			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			proto  = str(ip4_pkt.proto)
			sport = "0"
			dport = "0" 
			if proto == "6":
				tcp_pkt = pkt.get_protocol(tcp.tcp)
				sport = str(tcp_pkt.src_port)
				dport = str(tcp_pkt.dst_port)
			   
			if proto == "17":
				udp_pkt = pkt.get_protocol(udp.udp)
				sport = str(udp_pkt.src_port)
				dport = str(udp_pkt.dst_port)
				
			self.logger.info("Packet from the switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src, src_ip, dst_ip, in_port)
#############################################################################################################################			
			





























			# PACKET CLASSIFICATION FUNCTION: it returns action: "allow" or "deny"
			#here we call our tree and function which were defined below of script 
			#class TREE and NODE are out of Class SIMPLEswitch
			#if here put code of call , the program will be called iteratively

			action_rule = self.linear_classification(src_ip, dst_ip, proto, sport, dport)
			#action_rule = "allow"	
			#keep in mind that u need follow the order of calling the function based on your fuckin logic and script
			##############################################
			#last issue 30.03.20 how obtain all rule from finding_prefix	
			
			############################################## here handle F1 field source ip ################################
			

			

####################################################################################################
			
			


			

				



			print "proto of pkt", proto
			print "sport of pkt", sport
			print "dport of pkt", dport

			binn_scr_ip=fromIPtoBinary(src_ip)
			print "src address of pkt", binn_scr_ip
			

			s1=fromIPtoBinary(self.classify["r1"][SRC_IP])
			s2=fromIPtoBinary(self.classify["r2"][SRC_IP])
			s3=fromIPtoBinary(self.classify["r3"][SRC_IP])
			s4=fromIPtoBinary(self.classify["r4"][SRC_IP])
			
			chunk=[]
			chunk.append(s1)
			chunk.append(s2)
			chunk.append(s3)
			chunk.append(s4)
			
			f1=Tree()
			i=0
			while i<=len(s1):
				k=0
				tupl=[]
				while k<len(chunk):
					
					tupl.append(chunk[k][:i])
					#print chunk[k][:i]
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					f1.add_node(str(ke))
				#print "tuples", tupl

				i+=1

			
				

			for rule in self.classify:
				f1.add_rule(fromIPtoBinary(self.classify[rule][SRC_IP]),0,rule,None)
				
			
						
			


			
			ff=f1.finding_prefix(self.classify["r2"][SRC_IP],f1.root,0)
			
			print "best prefix field 1", ff
			
			dataf1=[]
			for i in buk:
				if i!=[]:
					
					for k in i:
						dataf1.append(k)
			


			
					
			
			f1_all= [item for item, count in collections.Counter(dataf1).items() if count > 1]
			print "all data===of f1 while searching" ,f1_all

			
			


################################## DST-IP handlin#######################################



			ss1=fromIPtoBinary(self.classify["r1"][DST_IP])
			ss2=fromIPtoBinary(self.classify["r2"][DST_IP])
			ss3=fromIPtoBinary(self.classify["r3"][DST_IP])
			ss4=fromIPtoBinary(self.classify["r4"][DST_IP])
			
									
			chunk2=[]
			chunk2.append(fromIPtoBinary(self.classify["r1"][DST_IP]))
			chunk2.append(fromIPtoBinary(self.classify["r2"][DST_IP]))
			chunk2.append(fromIPtoBinary(self.classify["r3"][DST_IP]))
			chunk2.append(fromIPtoBinary(self.classify["r4"][DST_IP]))
		


			f2=Tree()
			
			
			i=0
			while i<=len(ss1):
				k=0
				tupl=[]
				while k<len(chunk2):
					
					tupl.append(chunk2[k][:i])
					#print chunk[k][:i]
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					f2.add_node(str(ke))
				#print "tuples", tupl
#
				i+=1
			
			####addin rule for F2 field 
			for rule in self.classify:
				f2.add_rule(fromIPtoBinary(self.classify[rule][DST_IP]),0,rule,None)

			f2.add_rule('110001010000000000000000000',0,"ruleeee4",None)
			
			ff2=f2.finding_prefix(self.classify["r4"][DST_IP],f2.root,0)
			print "\n\n\nprefix--field f2==========",ff2
			#print "buk ===2", buk
			dataf2=[]
			for i in buk:
				if i!=[]:
					
					for k in i:
						dataf2.append(k)


			all_f2=[item for item, count in collections.Counter(dataf2).items() if count > 1]
			
			clear_f2=list(set(all_f2)-set(f1_all))
			print "clear mmmmmmmmm fffield2222", clear_f2

			
			
#############################################handling filed 3 proto######################################################
		

			prt1=str(bin(int(self.classify["r1"][PROTO]))[2:])
			prt2=str(bin(int(self.classify["r2"][PROTO]))[2:])
			prt3=str(bin(int(self.classify["r3"][PROTO]))[2:])
			prt4=str(bin(int(self.classify["r4"][PROTO]))[2:])
			
			
			bin_proto=str(bin(int(proto))[2:])
			print "my protocol",str(bin(int(proto))[2:])
			
			chunk3=[]
			prep=[]
			prep.append(prt1)
			prep.append(prt2)
			prep.append(prt3)
			prep.append(prt4)
			#print "max ",len( max(prep,key=len))			
			for i in prep:
				#print "padded list", i.ljust(len( max(prep,key=len)),'0')
				chunk3.append(i.ljust(len( max(prep,key=len)),'0'))
			print chunk3
			
			
			
			


			f3=Tree()
			
			
			i=0
			while i<=len(chunk3[1]):
				k=0
				tupl=[]
				while k<len(chunk3):
					
					tupl.append(chunk3[k][:i])
					#print chunk3[k][:i]
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					#print "===", ke\
					print str(ke)
					f3.add_node(str(ke))
					
				#print "tuples", tupl
#
				i+=1

			f3.add_node("111")


			
			for rule in sorted(self.classify):
				
				f3.add_rule(str(bin(int(self.classify[rule][PROTO]))[2:]),0,rule,None)
			f3.add_rule("11",0,"rrr",None)
			f3.add_rule("111",0,"rere",None)	
			
			
			
			ff3=f3.finding_prefix_one(bin_proto,f3.root,0)
			
			print "\n\n\nprefix protocol", ff3
			#print "all proto ", sort
			#f1.print_tree(f1.root)
			data_proto=[]
			for i in sort:
				if i!=[]:
					
					for k in i:
						data_proto.append(k)
			#print "we have all data in F1", dataf1


			
					
			#buk2=str(buk)
			all_proto= [item for item, count in collections.Counter(data_proto).items() if count > 1]
			print "all data===of proto while searching" ,all_proto

			




################################## handlin source port Field 4#####################################################

			print "\nmy port source", sport
			bin_sport=str(bin(int(sport))[2:])
			sprt1=self.classify["r1"][SPORT]
			sprt2=self.classify["r2"][SPORT]
			sprt3=self.classify["r3"][SPORT]
			sprt4=self.classify["r4"][SPORT]
			all_sport=[]
			all_sport.append(sprt1)
			all_sport.append(sprt2)
			all_sport.append(sprt3)
			all_sport.append(sprt4)
			

			all_sport=list(dict.fromkeys(all_sport))
			data=[]
			
			for i in all_sport:
				if i!="*":
					
					k=str(bin(int(i))[2:])
					data.append(k)
				
			#print "aaaaaaa",data

			same_sport=[]
			for i in data:
				
				same_sport.append(i.ljust(len( max(data,key=len)),'0'))
				
					

			f4=Tree()
			i=0
			while i<=len(same_sport[1]):
				k=0
				tupl=[]
				while k<len(same_sport):
					
					tupl.append(same_sport[k][:i])
					#print chunk3[k][:i]
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					#print "===", ke\
					#print "kekekeke",str(ke)
					f4.add_node(str(ke))
					
				#print "tuples", tupl
#
				i+=1
			
			for rule in sorted(self.classify):
				#print "=========", rule
				if self.classify[rule][SPORT]!="*":
					#print "=========",str(bin(int(self.classify[rule][SPORT]))[2:])
					f4.add_rule(str(bin(int(self.classify[rule][SPORT]))[2:]),0,rule,None)
				else:
					#self.classify[rule][SPORT]=""
					f4.add_rule("",0,rule,None)
			f4.add_rule("",0,"ahaha", None)
			f4.add_rule("111101",0,"rule222", None)

			
			

			fsport=f4.finding_prefix_one("1111011",f4.root,0)
			
			print "\n\n\nprefix source port", fsport


			data_sport=[]
			for i in sort:
				if i!=[]:
					
					for k in i:
						data_sport.append(k)

			

			all_sport= [item for item, count in collections.Counter(data_sport).items() if count > 1]
			print "all data===of sport while searching" ,all_sport

			





##########################################handling field 5############# handling destination port#################################



			print "my port destination", dport
			bin_dport=str(bin(int(dport))[2:])
			dprt1=self.classify["r1"][DPORT]
			dprt2=self.classify["r2"][DPORT]
			dprt3=self.classify["r3"][DPORT]
			dprt4=self.classify["r4"][DPORT]
			all_dport=[]
			all_dport.append(dprt1)
			all_dport.append(dprt2)
			all_dport.append(dprt3)
			all_dport.append(dprt4)
			




			all_dport=list(dict.fromkeys(all_dport))
			data=[]
			
			for i in all_dport:
				if i!="*":
					
					k=str(bin(int(i))[2:])
					data.append(k)
				
			
			same_dport=[]
			for i in data:
				
				same_dport.append(i.ljust(len( max(data,key=len)),'0'))


			

			f5=Tree()
			i=0
			while i<=len(same_dport[1]):
				k=0
				tupl=[]
				while k<len(same_dport):
					
					tupl.append(same_dport[k][:i])
					#print chunk3[k][:i]
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					#print "===.................", ke
					#print "kekekeke",str(ke)
					f5.add_node(str(ke))
					
				#print "tuples", tupl
#
				i+=1

			for rule in sorted(self.classify):
				#print "=========", rule
				if self.classify[rule][DPORT]!="*":
					#print "=========",str(bin(int(self.classify[rule][SPORT]))[2:])
					f5.add_rule(str(bin(int(self.classify[rule][DPORT]))[2:]),0,rule,None)
				else:
					#self.classify[rule][SPORT]=""
					f5.add_rule("",0,rule,None)


			


			fdport=f5.finding_prefix_one(bin_dport,f5.root,0)


			print"\n\n\nbest prefix in dest port:",fdport



			data_dport=[]
			for i in sort:
				if i!=[]:
					
					for k in i:
						data_dport.append(k)

			

			all_dport= [item for item, count in collections.Counter(data_dport).items() if count > 1]
			clear_dport=list(set(all_dport)-set(all_sport)-set(all_proto))
			print "clear mmmmmmmmm dest port", clear_dport

			
			for rule in self.classify:
					print "rule", type(rule)
					print "rule", len(rule)
			
			res = any(ele in ff for ele in ff2) 
			print "@@@@@@@@@@@@@@@@@@@@@@@@@@",res
			if any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3)==True:
				#print "action", self.classify[ff2][ACTION]
				for i in ff2:
					action=self.classify[i][ACTION]
					

				print action
				print "cho"
			
			maco=self.hierarchical_classification(ff,f1_all,ff2,clear_f2,ff3,all_proto,fsport,all_sport,fdport,all_dport)
			



			print "\n\n\nResults from hierarchical_classification",maco
			action=maco





















			if action_rule == "allow":			
				# IP LOOKUP FUNCTION: it is zero if it didn't find a solution
				destination_switch_IP = self.linear_search(dst_ip)
				
				if destination_switch_IP != "0":
					datapath_dst = get_datapath(self,int(self.switch[destination_switch_IP][DPID]))
					dpid_dst = datapath_dst.id			
					self.logger.info(" --- Destination present on switch: %s", dpid_dst)
					
					# Shortest path computation
					path = nx.shortest_path(self.net,dpid_src,dpid_dst)
					self.logger.info(" --- Shortest path: %s", path)
					
					if len(path) == 1:
						In_Port = self.mac_to_port[dpid_src][src]
						Out_Port = self.mac_to_port[dpid_dst][dst]	
						actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
						actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
						match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst)
						self.add_flow(datapath, 1, match_1, actions_1)

						actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
						data = msg.data
						pkt = packet.Packet(data)
						eth = pkt.get_protocols(ethernet.ethernet)[0]
						# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
						pkt.serialize()
						out = datapath.ofproto_parser.OFPPacketOut(
							datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
							actions=actions, data=pkt.data)
						datapath.send_msg(out)
						
						
					elif len(path) == 2:				
						path_port = self.net[path[0]][path[1]]['port']
						actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
						data = msg.data
						pkt = packet.Packet(data)
						eth = pkt.get_protocols(ethernet.ethernet)[0]
						eth.src = self.ip_to_mac[src_ip] 
						eth.dst = self.ip_to_mac[dst_ip] 
						# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
						pkt.serialize()
						out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
							actions=actions, data=pkt.data)
						datapath.send_msg(out)	
						
					elif len(path) > 2:
						# Add flows in the middle of the network path 
						for i in range(1, len(path)-1):							
							In_Port = self.net[path[i]][path[i-1]]['port']
							Out_Port = self.net[path[i]][path[i+1]]['port']
							dp = get_datapath(self, path[i])
							# self.logger.info("Matched OpenFlow Rule = switch: %s, from in port: %s, to out port: %s, source IP: %s, and destination IP: %s", path[i], In_Port, Out_Port, src_ip, dst_ip)
						
							actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port)]
							match_1 = parser.OFPMatch(in_port=In_Port, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
							self.add_flow(dp, 1, match_1, actions_1)
						
						path_port = self.net[path[0]][path[1]]['port']
						actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
						data = msg.data
						pkt = packet.Packet(data)
						eth = pkt.get_protocols(ethernet.ethernet)[0]
						# change the mac address of packet
						eth.src = self.ip_to_mac[src_ip] 
						eth.dst = self.ip_to_mac[dst_ip] 
						# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
						pkt.serialize()
						out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
							actions=actions, data=pkt.data)
						datapath.send_msg(out)

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]		
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)		
		# print "**********List of links"
		# print self.net.edges()
        #for link in links_list:
	    #print link.dst
            #print link.src
            #print "Novo link"
	    #self.no_of_links += 1		

#-------------------------------------------------------------------------------------------------------
		
	def linear_search(self, dst_ip):
		self.logger.info(" --- IP address Lookup") 
		if dst_ip in self.lookup:
			destination_switch_IP = self.lookup[dst_ip]
			return destination_switch_IP
		else:
			destination_switch_IP = "0"
			return destination_switch_IP
	def hierarchical_classification(self,ff,f1_all,ff2,clear_f2,ff3,all_proto,fsport,all_sport,fdport,all_dport):
		if any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3) and any(ele in ff3 for ele in fsport) and any(ele in fsport for ele in fdport)==True:
				print "tier1"
				for i in ff2:
					acca=self.classify[i][ACTION]
				
				#print "action", self.classify[ff2][ACTION]
				#for i in ff2:
				#	action=self.classify[i][ACTION]
		#if res = any(ele in ff for ele in ff2) ==True:
		elif any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3) and any(ele in ff3 for ele in fsport)==True:
			print "tier2"
			for i in ff2:
				acca=self.classify[i][ACTION]
			
		elif any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3) ==True:
			print "tier3"
			for i in ff2:
				acca=self.classify[i][ACTION]
		elif any(ele in ff for ele in ff2)==True:
			print "tier4"
			for i in ff2:
				acca=self.classify[i][ACTION]
		else:
			print "loooh"
		
		return acca


		
	def linear_classification(self, src_ip, dst_ip, proto, sport, dport):
		action = "deny"
		self.logger.info(" --- Packet classification") 

		# check matching rule
		for rule in sorted(self.classify):
			match = self.classify[rule]
			if (match[SRC_IP] == src_ip or match[SRC_IP] == "*") and \
				(match[DST_IP] == dst_ip or match[DST_IP] == "*") and \
				(match[PROTO]  == proto  or match[PROTO]  == "*") and \
				(match[SPORT]  == sport  or match[SPORT]  == "*") and \
				(match[DPORT]  == dport  or match[DPORT]  == "*") :
				self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[ACTION]))
				action = match[ACTION]
				self.counters[rule] = self.counters[rule] + 1
				return action
		
		return action

class Node():
	

	#initialization of a node for the tree
	def __init__(self,key):
		self.key = key
		self.left = None
		self.right = None
		self.parent = None
		self.rule = []


		
	#adding a rule address to the tree
	def add_rule(self, rule):
		
		
		#self.rule=rule
		self.rule.append(rule)
	
  
class Tree():

       	
        #initialization of the tree setting the root to None
        def __init__(self):
		self.root = None

		
	#building the tree appending one node
	def add_node(self,key,node=None):
                global length
                #setting the root
		if node is None:
			node = self.root
		
		if self.root is None:
			self.root = Node(key)
		else: 
                        if (key[length]=='0'):
                                length=length+1 
				#adding left node      
				if node.left is None:
					node.left = Node(key)
					node.left.parent = node
                                        length=0
					return 
				else:
					#adding nodes to the left one
					return self.add_node(key,node = node.left)
			else:
                                length=length+1
				#adding right node
				if node.right is None:
					node.right = Node(key)
					node.right.parent = node
                                        length=0
					return 
				else:
					#adding nodes to the right one 
					return self.add_node(key,node = node.right)
	

	

############################################################################################################################
	#searching a specific node to assign him a rulle		
	def add_rule(self,key, l, rule, node):
		
		if node is None:
			node = self.root


		if self.root.key == key:
			print "key is at the root::", node.key
			node.add_rule(rule)
			print "rule is ::",rule
			return self.root
		else:
			#### Never put rule a*, 0, 1 ####
			
			if len(node.key) == len(key):

				#print "\nact", rule
				#rule=rule+rule
				#print "added to node: ", node.key
				

				
				node.add_rule(rule)
				#print "s", node.add_rule(rule)
			
				l = 0
				return 
			elif key[l] == "0" and node.left is not None:
				l = l + 1
				#print "s", key
				return self.add_rule(key, l, rule, node = node.left)
			
			elif key[l] == "1" and node.right is not None:
				l = l + 1
				return self.add_rule(key, l, rule, node = node.right)
			else:
				l = 0 
				return None
	###################################################################################################################
	#print of the tree with nodes ordered by level	
	def print_tree(self, head, queue=deque()):
		if head is None:
       			return
    		print "\nkey: ", head.key, "\nrule: ", head.rule
    		
		if head.right is not None:
			print "Node right: ", head.right.key
		else:	print "Node right:  --"
		if head.left is not None:
			print "Node left: ", head.left.key
		else:	print "Node left:  --"
    		[queue.append(node) for node in [head.left, head.right] if node]
    		if queue:
        		self.print_tree(queue.popleft(), queue)

	def finding_prefix(self, IP_add_str, n1, i):
		#global buk
		
		
		global last_prefix
			
		IP_add_bin = fromIPtoBinary(IP_add_str) 
		#IP_add_bin = IP_add_str 
		IP_add_bin+="00"		
		#sort=[]

		##############################
		#sort=[]
		#buk=[]
		buk.append(n1.rule)
		
		if last_prefix == '*':
			
			return "*" 
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1 

				if n1.rule is not None:
					
					last_prefix= n1.rule 
					
					
				return self.finding_prefix(IP_add_str, n1.left, i) 

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1 
				

				if n1.rule is not None:
					last_prefix = n1.rule 

						
				return self.finding_prefix(IP_add_str, n1.right, i) 
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule 
					#print "=========smotri",data
				else:
					
					return last_prefix 
		else:
			
			return last_prefix 


	def finding_prefix_one(self, IP_add_str, n1, i):
		#global buk
		
		
		global last_prefix
		if IP_add_str=="*":
			print "root"
			print "Nothing"
		#IP_add_bin = fromIPtoBinary(IP_add_str) 
		IP_add_bin = IP_add_str 
		IP_add_bin+="1"		
		#sort=[]
		#print "lllllllllllllll", last_prefix
		##############################
		sort.append(last_prefix)
		#buk=[]
		#buk.append(n1.rule)
		
		if last_prefix == '*':
			
			return "*" 
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1 

				if n1.rule is not None:
					
					last_prefix= n1.rule 
					
					
				return self.finding_prefix_one(IP_add_str, n1.left, i) 

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1 
				

				if n1.rule is not None:
					last_prefix = n1.rule 

						
				return self.finding_prefix_one(IP_add_str, n1.right, i) 
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule 
					#print "=========smotri",data
				else:
					
					return last_prefix 
		else:
			
			return last_prefix 

		

		
#here we put additional script which is out of Class node , bcz we dont need to relate it inside the class








def fromBinarytoIP(string):
	splitter = 8
	divided = [string[i:i+splitter] for i in range(0, len(string), splitter)]
	decimal = []
	i = 0
	while i < 4:
		decimal.append(int(divided[i], 2))
		i = i + 1
	IPaddress = str(decimal[0])
	for i in range(1,4):
		IPaddress = IPaddress +'.'+ str(decimal[i])
	return str(IPaddress)


def fromIPtoBinary(string):
	if string=="*":
		print "hello"
		return
	else:
	
		w1, w2, w3, w4 = string.split(".")
		binaryN = [ str(bin(int(w1)))[2:], str(bin(int(w2)))[2:], str(bin(int(w3)))[2:], str(bin(int(w4)))[2:]]
		binaryN = paddingAddress(binaryN)
		addressIP = binaryN[0]
		i=1
		while i<4:
			addressIP = addressIP+binaryN[i]
			i=i+1
		return str(addressIP)


def paddingAddress(list):
	i = 0
	padded_list = list 
	while i < len(list):
		if len(list)<8:
			while len(padded_list[i]) < 8:
				padded_list[i] = '0' + padded_list[i]
		i = i + 1
	return padded_list








length=0
last_prefix=None 
global buk
buk=[]
global sort
sort=[]
#f2=Tree()
#f2.add_node("*")
##f2.add_node_F2("0")
#f2.add_node("1")
##f2.add_node_F2("00")
#f2.add_node("0")
#f2.add_node("00")
#f2.add_node("000")
#f2.add_node("0000")
#f2.add_node("0001")
#f2.add_node("01")
#f2.add_node("010")
#f2.add_node("0100")
#f2.add_node("0101")
#f2.add_node("011")
#f2.add_node("0110")
#f2.add_node("11")
#f2.add_node("111")
#f2.add_node("1111")
#f2.add_node("10")
#f2.add_node("100")
#f2.add_node("1000")
#f2.add_node("1001")






#adding rule 

#f2.add_rule("1001",0,"rule1",None)
#f2.add_rule("1000",0,"rule2",None)
#f2.add_rule("0101",0,"rule3",None)
#f2.add_rule("0110",0,"rule4",None)
#f2.add_rule("0100",0,"rule5",None)
#f2.add_rule("0001",0,"rule6",None)
#f2.add_rule("0100",0,"rule7",None)
#f2.add_rule("1111",0,"rule8",None)









	
app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')		
