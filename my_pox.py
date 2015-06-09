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

mac_learning = {}
switch_ports = {}

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

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
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

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
    if not self.transparent:
      if packet.type == packet.LLDP_TYPE:
          drop()
  	  log.debut("Switch %s dropped LLDP packet", self)
	  return

    if packet.dst.is_multicast:
      	flood()
      	log.debug("Switch %s flooded multicast 0x%0.4X type packet", self, packet.type)
    else:
      if packet.dst not in self.macToPort: 
        flood("Port for %s unknown -- flooding" %(packet.dst,))
      else:
        port = self.macToPort[packet.dst]
	if port == event.port:
	  log.warning("Same port for packet from %s -> %s on %s.%s. Drop." %(packet.sorc, packet.dst, dpid_to_str(event.dpid), port))
	  drop(10)
	  return

    else:
      if packet.type == packet.ARP_TYPE:
       drop()
       msg = of.ofp_packet_out()
       msg.data = event.ofp.data
       msg.actions.append(of.ofp_action_output(port = event.port))
       self.connection.send(msg)
       log.debug("Switch %s processed unicast ARP (0x0807) packet, send to recipient by switch %s", self, util.dpid_to_str(dst.dpid)) 
    else:
        #log.debug("Switch %s received PacketIn of type 0x%0.4X, reveived form %s.%s", self, packet.type, util.dpid_to_str(event.dpid), event.port)
	#dst = packet.dst
	#prev_path = _get_path(self.connection.dpid, dst.dpid)
	#if prev_path is None:
	#	flood()
	#	return
	#log.debug("Path from %s to %s over path %s", packet.src, packet.dst, prev_path)
	
	drop()
	msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp.data
        self.connection.send(msg)


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

