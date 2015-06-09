# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
import pox.lib.util as util

from collections import namedtuple

log = core.getLogger()

switches = {}
switch_ports = {}

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class ofp_match_withHash(of.ofp_match):
	##Our additions to enable indexing by match specifications
	@classmethod
	def from_ofp_match_Superclass(cls, other):	
		match = cls()
		
		match.wildcards = other.wildcards
		match.in_port = other.in_port
		match.dl_src = other.dl_src
		match.dl_dst = other.dl_dst
		match.dl_vlan = other.dl_vlan
		match.dl_vlan_pcp = other.dl_vlan_pcp
		match.dl_type = other.dl_type
		match.nw_tos = other.nw_tos
		match.nw_proto = other.nw_proto
		match.nw_src = other.nw_src
		match.nw_dst = other.nw_dst
		match.tp_src = other.tp_src
		match.tp_dst = other.tp_dst
		return match
		
	def __hash__(self):
		return hash((self.wildcards, self.in_port, self.dl_src, self.dl_dst, self.dl_vlan, self.dl_vlan_pcp, self.dl_type, self.nw_tos, self.nw_proto, self.nw_src, self.nw_dst, self.tp_src, self.tp_dst))

class Path(object):
	def __init__(self, src, dst, prev, first_port):
		self.src = src
		self.dst = dst
		self.prev = prev
		self.first_port = first_port
	
def _get_path(src, dst):
    #Bellman-Ford algorithm
    keys = switches.keys()
    distance = {}
    previous = {}
	
    for dpid in keys:
	distance[dpid] = float("+inf")
	previous[dpid] = None

    distance[src] = 0
    for i in range(len(keys)-1):
	for u in adj.keys(): #nested dict
		for v in adj[u].keys():
			w = 1
			if distance[u] + w < distance[v]:
				distance[v] = distance[u] + w
				previous[v] = u 

    for u in adj.keys(): #nested dict
	for v in adj[u].keys():
		w = 1
		if distance[u] + w < distance[v]:
			log.error("Graph contains a negative-weight cycle")
			return None
	
    first_port = None
    v = dst
    u = previous[v]
    while u is not None:
    	if u == src:
		first_port = adj[u][v]
		
    v = u
    u = previous[v]
				
    return Path(src, dst, previous, first_port)  #path

def _install_path(prev_path, match):
	dst_sw = prev_path.dst
	cur_sw = prev_path.dst
	dst_pck = match.dl_dst
	
	msg = of.ofp_flow_mod()
	msg.match = match
	msg.idle_timeout = 10
	msg.flags = of.OFPFF_SEND_FLOW_REM	
	msg.actions.append(of.ofp_action_output(port = mac_learning[dst_pck].port))
	log.debug("Installing forward from switch %s to output port %s", util.dpid_to_str(cur_sw), mac_learning[dst_pck].port)
	switches[dst_sw].connection.send(msg)
	
	next_sw = cur_sw
	cur_sw = prev_path.prev[next_sw]
	while cur_sw is not None: #for switch in path.keys():
		msg = of.ofp_flow_mod()
		msg.match = match
		msg.idle_timeout = 10
		msg.flags = of.OFPFF_SEND_FLOW_REM
		log.debug("Installing forward from switch %s to switch %s output port %s", util.dpid_to_str(cur_sw), util.dpid_to_str(next_sw), adj[cur_sw][next_sw])
		msg.actions.append(of.ofp_action_output(port = adj[cur_sw][next_sw]))
		switches[cur_sw].connection.send(msg)
		next_sw = cur_sw
		
		cur_sw = prev_path.prev[next_sw]

class LearningSwitch (object):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  thatse:

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  """
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    packet = event.parsed

    def forward(port):
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = port))
      if event.ofp.buffer_id is not None:
	msg.buffer_id = event.ofp.buffer_id
      else:
        msg.data = event.ofp.data
      msg.in_port = event.port
      self.connection.send(msg)   

    def flood (message = None):
      """ Floods the packet """
      for (dpid,switch) in switches.iteritems():
	  msg = of.ofp_packet_out()
	  if switch == self:
	      if event.ofp.buffer_id is not None:
	         msg.buffer_id = event.ofp.buffer_id
	      else:
	  	 msg.data = event.ofp.data
	      msg.in_port = event.port
	  else:
	      msg.data = event.ofp.data
	  ports = [p for p in switch.connection.ports if (dpid,p) not in switch_ports]
	  if len(ports) > 0:
	      for p in ports:
		  msg.actions.append(of.ofp_action_output(port = p))
	      switches[dpid].connection.send(msg)

    def drop ():

      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
	event.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    log.debug("Received PacketIn")

    self.macToPort[packet.src] = event.port
    #SwitchPort = namedturpl('SwitchPoint', 'dpid port') 

    #if (event.dpid,event.port) not in switch_ports:
        #mac_learning[packet.src] = SwitchPort(event.dpid, event.port)
    #if not self.transparent:
    if packet.type == packet.LLDP_TYPE:
          drop()
  	  log.debut("Switch %s dropped LLDP packet", self)
	
    elif packet.dst.is_multicast:
      	flood()
      	#log.debug("Switch %s flooded multicast 0x%0.4X type packet", self, packet.type)
    elif packet.dst not in self.macToPort: 
        flood("Port for %s unknown -- flooding" %(packet.dst,))
    #else:
	#port = self.macToPort[packet.dst]
	#if port == event.port:
	 # log.warning("Same port for packet from %s -> %s on %s.%s. Drop." %(packet.sorc, packet.dst, dpid_to_str(event.dpid), port))
	  #drop(10)

    elif packet.type == packet.ARP_TYPE:
        drop()
        msg = of.ofp_packet_out()
        msg.data = event.ofp.data
        msg.actions.append(of.ofp_action_output(port = event.port))
        self.connection.send(msg)
        log.debug("Switch %s processed unicast ARP (0x0807) packet, send to recipient by switch %s", self, util.dpid_to_str(dst.dpid)) 
    else:
        log.debug("Switch %s received PacketIn of type 0x%0.4X, reveived form %s.%s", self, packet.type, util.dpid_to_str(event.dpid), event.port)
	dst = macToPort[packet.dst]
	prev_path = _get_path(self.connection.dpid, dst.dpid)
	if prev_path is None:
		flood()
		return
	log.debug("Path from %s to %s over path %s", packet.src, packet.dst, prev_path)
        if self.l3_matching == True: #only match on l2-properties, useful when doing experiments with UDP streams as you can insert a flow using ping and then start sending udp.
				
	   match = ofp_match_withHash()
           match.dl_src = packet.src
	   match.dl_dst = packet.dst
	   match.dl_type = packet.type
	   p = packet.next
	   if isinstance(p, vlan):
	       match.dl_type = p.eth_type
	       match.dl_vlan = p.id
	       match.dl_vlan_pcp = p.pcp
	       p = p.next
	   if isinstance(p, ipv4):
	      match.nw_src = p.srcip
	      match.nw_dst = p.dstip
	      match.nw_proto = p.protocol
	      match.nw_tos = p.tos
	      p = p.next
	   else:
	       match.dl_vlan = of.OFP_VLAN_NONE
	       match.dl_vlan_pcp = 0
				
	else:
	    match = ofp_match_withHash.from_packet(packet)
			
	_install_path(prev_path, match)
	
        drop()
	msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp.data
        self.connection.send(msg)

    	def _handle_ConnectionDown(self, event):
		log.debug("Switch %s going down", util.dpid_to_str(self.connection.dpid))
		del switches[self.connection.dpid]
		#pprint(switches)
	

class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))

