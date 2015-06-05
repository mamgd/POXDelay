from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time

from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str, str_to_bool
from pox.core import core

import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.util as util

from datetime import datetime

from collections import defaultdict
from collections import namedtuple
import pox.lib.packet as pkt
import struct
from pox.lib.addresses import IPAddr,EthAddr

import time

log = core.getLogger()

class Monitoring (object):
	
	def __init__(self,postfix):
		log.debug("Monitoring comes up")
	
	def _startup():
		
		core.openflow.addListeners(self,priority=0xfffffffe)
		core.forwarding.l2_learning.addListeners(self)
		log.debug('addListeners l2_learning')

		self.decreaseTimer = False
		self.increaseTimer = False
		self.t = Timer(1, self._timer_MonitorPaths, recurring = True)

		self.f = open("output.%s.csv"%postfix, "w")
		self.f.write("Experiment,Switch,SRC_IP,DST_IP,SRC_PORT,DST_PORT,Packet_Count,Byte_Count,Duration_Sec,Duration_Nsec,Delta_Packet_Count,Delta_Byte_Count,Delta_Duration_Sec,Delta_Duration_Nsec\n")
		self.f.flush()

		self.f2 = open("delay.%s.csv"%postfix, "w")
		self.f2.write("MeasurementType,Src/Initiator,Dst/Switch,Delay\n")
		self.f2.flush()
		
		self.experiment = postfix
		
		log.debug("Monitoring starting")
		core.call_when_ready(startup, ('forwarding.l2_learning'))
		
	def __del__(self):
		
		self.f.close()
	
	def _handle_NewSwitch (self, event):
		switch = event.switch
		log.debug("New switch to Monitor %s", switch.connection)
		switches[switch.connection.dpid] = switch
		switch.addListeners(self)
		
	def _handle_NewFlow(self, event):
		match = event.match
		path = event.prev_path
		adj = event.adj
		log.debug("New flow to monitor %s", str(match))
		log.debug(path._tuple_me())
		
		_install_monitoring_path(path, adj)
		
		if path not in monitored_paths:
			monitored_paths[path] = set([match])
			monitored_pathsById[id(path)] = path
			sw = path.dst
			while sw is not None:
				if sw not in monitored_pathsBySwitch:
					monitored_pathsBySwitch[sw] = set([path])
				else:
					monitored_pathsBySwitch[sw].add(path)
				#pprint(monitored_pathsBySwitch[sw])
				sw = path.prev[sw]
		else:
			monitored_paths[path].add(match)
		#pprint(monitored_paths[path])
			
		monitored_pathsByMatch[match] = path
			
	def _handle_FlowRemoved(self, event):
		match = ofp_match_withHash.from_ofp_match_Superclass(event.ofp.match)
		path = monitored_pathsByMatch.pop(match, None)
		if path is not None:
			log.debug("Removing flow")
			monitored_paths[path].remove(match)
			if not monitored_paths[path]:
				del monitored_paths[path]
				del monitored_pathsById[id(path)]
				sw = path.dst
				
				while sw is not None: 
					monitored_pathsBySwitch[sw].remove(path)
					if not monitored_pathsBySwitch[sw]:
						del monitored_pathsBySwitch[sw]
					pprint(monitored_pathsBySwitch[sw])
			
					sw = path.prev[sw]
			pprint(monitored_paths[path])
			
	def _handle_BarrierIn (self, event):
		timeRecv = time.time()
		dpid = event.dpid
		xid = event.xid
		if xid not in barrier:
			return
		
		(initiator, prevTime) = barrier[xid]
		log.debug("Delay from switch %s initiated by %s = %f"%(util.dpid_to_str(dpid), util.dpid_to_str(initiator), timeRecv - prevTime))
		self.f2.write("Switch,%s,%s,%f\n"%(util.dpid_to_str(initiator), util.dpid_to_str(dpid), timeRecv - prevTime))
		self.f2.flush()
		del barrier[xid]
		return EventHalt	
		
def launch (postfix=datetime.now().strftime("%Y%m%d%H%M%S")):
	
	"""
	Starts the component
	"""
	core.registerNew(Monitoring, postfix)
		
