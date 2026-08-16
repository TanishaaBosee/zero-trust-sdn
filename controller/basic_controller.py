#!/usr/bin/env python3
"""
basic_controller.py - Baseline RYU Controller (NO Zero Trust)
================================================================
This controller is intentionally kept IDENTICAL in switching behaviour
to ryu_controller.py (same L2 learning logic), but it has NO Zero Trust
middleware and NO northbound verification API.

Why do we need it?
--------------------
To prove the performance overhead of the proposed Zero Trust framework,
we must compare:
    Baseline SDN  (this file)      vs   Zero Trust SDN (ryu_controller.py)

Everything that differs between the two runs is caused ONLY by the
Zero Trust verification pipeline (authentication, RBAC/ABAC, trust
scoring etc.) -> that number is the "security overhead" we report in
the research paper.

Run with:  sudo ryu-manager controller/basic_controller.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types


class BasicController(app_manager.RyuApp):
    """Baseline SDN controller: plain L2 learning switch, no security."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BasicController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Register switch and install table-miss forward-to-controller."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {})
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Same learning-switch logic as the ZT controller."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)
        if not eth:
            return
        eth = eth[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst, src = eth.dst, eth.src
        self.mac_to_port[dpid][src] = in_port

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)
            out_actions = [parser.OFPActionOutput(out_port)]
        else:
            out_actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=out_actions,
                                  data=msg.data)
        datapath.send_msg(out)