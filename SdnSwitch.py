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

  '''
  What I need to do
  - Intercept ARP request
  - Select which of the two servers to use for the request, and send the MAC address back to the sender host.
  - Add forwarding rules to map the virtual IP address with the real IP address of the selected server. The host and the server must be connected in both directions.
  '''
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
      #TODO this is almost certainly wrong; I'm just hard coding MAC addresses here
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

      arp_msg = of.ofp_packet_out()
      arp_msg.data = ether.pack()
      arp_msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      arp_msg.in_port = in_port
      event.connection.send(arp_msg)
      log.info(f"ARP reply sent to {packet.payload.protosrc}: {packet.payload.protodst} is-at {reply.hwsrc}")

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

        # forwarding
        # msg = of.ofp_packet_out()
        # msg.data = packet.pack()
        # msg.actions.append(of.ofp_action_output(port = out_port))
        # msg.in_port = in_port
        # event.connection.send(arp_msg)
        # log.info("Forwarded ping to server")
      # else:
      #   of_msg = of.ofp_flow_mod()
      #   of_msg.match.in_port = in_port
      #   of_msg.match.dl_type = 0x800
      #   of_msg.match.nw_src = packet.payload.protosrc
      #   of_msg.match.nw_dst = packet.payload.protodst
      #   of_msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.10"))) #TODO HARD CODED THIS ISN'T FUNCTIONAL
      #   #of_msg.actions.append(of.ofp_action_dl_addr.set_dst(reply.hwsrc))
      #   of_msg.actions.append(of.ofp_action_output(port = out_port))
      #   event.connection.send(of_msg)
      #   log.info(f"OpenFlow rule set: match traffic from inport {in_port} with source {packet.payload.protosrc} and destination {packet.payload.protodst}, send to outport {out_port} with source {reply.protosrc}")  
    else:
      log.info("Ignoring non-request ARP packet")
  elif packet.type == packet.IP_TYPE:
    msg = of.ofp_packet_out()
    msg.data = packet.pack()
    if packet.payload.protosrc == IPAddr("10.0.0.1") or packet.payload.protosrc == IPAddr("10.0.0.3") :
      msg.actions.append(of.ofp_action_output(port = 5))
    elif packet.payload.protosrc == IPAddr("10.0.0.2") or packet.payload.protosrc == IPAddr("10.0.0.4") :
      msg.actions.append(of.ofp_action_output(port = 6))
    msg.in_port = event.port
    event.connection.send(msg)
    log.info("Forwarded IP_TYPE packet to server")

    
'''
def _handle_ARP(self, event):
    # Note: arp.hwsrc is not necessarily equal to ethernet.src
    # (one such example are arp replies generated by this module itself
    # as ethernet mac is set to switch dpid) so we should be careful
    # to use only arp addresses in the learning code!
    squelch = False

    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
      return

    a = packet.find('arp')
    if not a: return

    log.debug("%s ARP %s %s => %s", dpid_to_str(dpid),
      {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
      'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

    if a.prototype == arp.PROTO_TYPE_IP:
      if a.hwtype == arp.HW_TYPE_ETHERNET:
        if a.protosrc != 0:

          if _learn:
            # Learn or update port/MAC info
            old_entry = _arp_table.get(a.protosrc)
            if old_entry is None:
              log.info("%s learned %s", dpid_to_str(dpid), a.protosrc)
              _arp_table[a.protosrc] = Entry(a.hwsrc)
            else:
              if old_entry.mac is True:
                # We never replace these special cases.
                # Might want to warn on conflict?
                pass
              elif old_entry.mac != a.hwsrc:
                if old_entry.static:
                  log.warn("%s static entry conflict %s: %s->%s",
                      dpid_to_str(dpid), a.protosrc, old_entry.mac, a.hwsrc)
                else:
                  log.warn("%s RE-learned %s: %s->%s", dpid_to_str(dpid),
                      a.protosrc, old_entry.mac, a.hwsrc)
                  _arp_table[a.protosrc] = Entry(a.hwsrc)
              else:
                # Update timestamp
                _arp_table[a.protosrc] = Entry(a.hwsrc)

          if a.opcode == arp.REQUEST:
            # Maybe we can answer

            if a.protodst in _arp_table:
              # We have an answer...

              r = arp()
              r.hwtype = a.hwtype
              r.prototype = a.prototype
              r.hwlen = a.hwlen
              r.protolen = a.protolen
              r.opcode = arp.REPLY
              r.hwdst = a.hwsrc
              r.protodst = a.protosrc
              r.protosrc = a.protodst
              mac = _arp_table[a.protodst].mac
              if mac is True:
                # Special case -- use ourself
                mac = event.connection.eth_addr
              r.hwsrc = mac
              e = ethernet(type=packet.type, src=event.connection.eth_addr,
                           dst=a.hwsrc)
              e.payload = r
              if packet.type == ethernet.VLAN_TYPE:
                v_rcv = packet.find('vlan')
                e.payload = vlan(eth_type = e.type,
                                 payload = e.payload,
                                 id = v_rcv.id,
                                 pcp = v_rcv.pcp)
                e.type = ethernet.VLAN_TYPE
              log.info("%s answering ARP for %s" % (dpid_to_str(dpid),
                str(r.protosrc)))
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port =
                                                      of.OFPP_IN_PORT))
              msg.in_port = inport
              event.connection.send(msg)
              return EventHalt if _eat_packets else None
            else:
              # Keep track of failed queries
              squelch = a.protodst in _failed_queries
              _failed_queries[a.protodst] = time.time()

    if self._check_for_flood(dpid, a):
      # Didn't know how to handle this ARP, so just flood it
      msg = "%s flooding ARP %s %s => %s" % (dpid_to_str(dpid),
          {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
          'op:%i' % (a.opcode,)), a.protosrc, a.protodst)

      if squelch:
        log.debug(msg)
      else:
        log.info(msg)

      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      event.connection.send(msg.pack())

    return EventHalt if _eat_packets else None
'''