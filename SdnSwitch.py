import pox
from pox.core import core
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.vlan import vlan
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.recoco import Timer
from pox.lib.revent import EventHalt

import pox.openflow.libopenflow_01 as of

def launch():
  log.info("Controller launched")
  core.addListenerByName("UpEvent", _handle_UpEvent)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

def _handle_UpEvent(event):
  log.info("Controller set up")

def _handle_ConnectionUp(event):
  log.info("Switch connected, listening for packets")

def _handle_PacketIn(event):
  dpid = event.connection.dpid
  in_port = event.port
  packet = event.parsed

  if not packet.parsed:
    log.warning("Packet received but couldn't be parsed")
    return

  log.debug(f"Packet received: {packet}")

  if packet.type == packet.ARP_TYPE:
    if packet.payload.opcode == arp.REQUEST:
      log.info(f"ARP request received; src: {packet.payload.protosrc} (port {in_port}), dest: {packet.payload.protodst}")
      reply = arp()
      out_port = 0
      reverse = False
      if packet.payload.protosrc == IPAddr("10.0.0.1") or packet.payload.protosrc == IPAddr("10.0.0.3") :
        reply.hwsrc = EthAddr("00:00:00:00:00:05")
        reply.protosrc = packet.payload.protodst
        realIP = IPAddr("10.0.0.5")
        out_port = 5
      elif packet.payload.protosrc == IPAddr("10.0.0.2") or packet.payload.protosrc == IPAddr("10.0.0.4") :
        reply.hwsrc = EthAddr("00:00:00:00:00:06")
        reply.protosrc = packet.payload.protodst
        realIP = IPAddr("10.0.0.6")
        out_port = 6
      else:
        reply.protosrc = packet.payload.protodst
        realIP = packet.payload.protodst
        if packet.payload.protodst == IPAddr("10.0.0.1"):
          reply.hwsrc = EthAddr("00:00:00:00:00:01")
          out_port = 1
        elif packet.payload.protodst == IPAddr("10.0.0.2"):
          reply.hwsrc = EthAddr("00:00:00:00:00:02")
          out_port = 2
        elif packet.payload.protodst == IPAddr("10.0.0.3"):
          reply.hwsrc = EthAddr("00:00:00:00:00:03")
          out_port = 3
        elif packet.payload.protodst == IPAddr("10.0.0.4"):
          reply.hwsrc = EthAddr("00:00:00:00:00:04")
          out_port = 4
        reverse = True
      reply.hwdst = packet.src
      reply.opcode = arp.REPLY
      reply.protodst = packet.payload.protosrc

      ether = ethernet()
      ether.type = ethernet.ARP_TYPE
      ether.dst = packet.src
      ether.src = reply.hwsrc
      ether.payload = reply

      if not reverse:
        of_msg = of.ofp_flow_mod()
        of_msg.match.in_port = in_port #this should match the port of the client host
        of_msg.match.dl_type = 0x800
        of_msg.match.nw_dst = packet.payload.protodst #this should match the virtual IP address
        of_msg.actions.append(of.ofp_action_nw_addr.set_dst(realIP)) #this should match the real IP address of the selected server
        #of_msg.actions.append(of.ofp_action_dl_addr.set_dst(reply.hwsrc))
        of_msg.actions.append(of.ofp_action_output(port = out_port))
        event.connection.send(of_msg)
        log.info(f"OpenFlow rule set: match traffic from inport {in_port} with destination {packet.payload.protodst}, send to outport {out_port} with destination {realIP}")
        
        # Reverse flow
        of_msg = of.ofp_flow_mod()
        of_msg.match.in_port = out_port
        of_msg.match.dl_type = 0x800
        of_msg.match.nw_src = realIP
        of_msg.match.nw_dst = packet.payload.protosrc
        of_msg.actions.append(of.ofp_action_nw_addr.set_src(packet.payload.protodst)) #TODO HARD CODED THIS ISN'T FUNCTIONAL
        #of_msg.actions.append(of.ofp_action_dl_addr.set_dst(reply.hwsrc))
        of_msg.actions.append(of.ofp_action_output(port = in_port))
        event.connection.send(of_msg)
        log.info(f"OpenFlow rule set: match traffic from inport {out_port} with source {realIP} and destination {packet.payload.protosrc}, send to outport {in_port} with source {packet.payload.protodst}") 

      arp_msg = of.ofp_packet_out()
      arp_msg.data = ether.pack()
      arp_msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      arp_msg.in_port = in_port
      event.connection.send(arp_msg)
      log.info(f"ARP reply sent to {packet.payload.protosrc}: {packet.payload.protodst} is-at {reply.hwsrc}")
    else:
      log.info("Ignoring non-request ARP packet")