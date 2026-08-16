#!/usr/bin/env python3
"""
ryu_controller.py - Main RYU SDN Controller with Zero Trust Middleware
========================================================================
This is the PRIMARY entry point of the Zero Trust SDN framework.
It is launched with:  sudo ryu-manager controller/ryu_controller.py

What this controller does:
1. Connects to OpenFlow 1.3 switches (OVS in Mininet) as a normal SDN controller
2. Acts as a simple L2 learning switch (switches learn MAC addresses,
   so hosts can ping/iperf each other)
3. Exposes a NORTHBOUND REST API on port 8080 (implemented with RYU WSGI).
   ALL network applications MUST send their requests through this API.
4. For EVERY northbound request it runs the full Zero Trust pipeline:
       Token  ->  API Key  ->  Device Identity  ->  RBAC  ->  ABAC
       ->  Behavioral Analysis  ->  Trust Scoring  ->  Policy Engine
   (modules: trust_verification.py, policy_engine.py,
             policy_enforcement_point.py, trust_scoring.py)
5. Only if the request passes ALL checks, the requested OpenFlow action
   (install flow / drop flow / install drop rule) is applied to the switch.
   Otherwise the request is rejected with HTTP 403.
6. Continuously updates the trust score of every application after
   every request and keeps statistics for the research evaluation.

Architecture:  Apps --HTTP--> [ZeroTrust GBP (this controller)] --> OVS switch
"""

import sys
import os
import json
import time
import logging

# Make sure the other Zero Trust modules can be imported no matter
# from which directory ryu-manager is launched.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.app.wsgi import WSGIApplication, ControllerBase, Response, route

# ------- Zero Trust framework modules (our own code) -------
from trust_verification import TrustVerificationEngine
from policy_engine import PolicyEngine
from policy_enforcement_point import PolicyEnforcementPoint
from trust_scoring import TrustScoring

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ZeroTrustController")


class ZeroTrustController(app_manager.RyuApp):
    """
    Main RYU application.

    OFP_VERSIONS tells RYU we speak OpenFlow 1.3.
    _CONTEXTS tells RYU to create the WSGI web server which will host
    our REST API (northbound interface) on port 8080.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ZeroTrustController, self).__init__(*args, **kwargs)

        # ---- Zero Trust components (one shared instance) ----
        # trust_engine: 7-layer verification pipeline + app registry
        self.trust_engine = TrustVerificationEngine(
            config_path=os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'config', 'policies.json'))
        # policy_engine: what policy matches this request (allow/deny)
        self.policy_engine = PolicyEngine(self.trust_engine)
        # pep: orchestrates verify -> decide -> enforce, and keeps counters
        self.pep = PolicyEnforcementPoint(self.trust_engine, self.policy_engine)
        # scoring: separate module that tracks trust score history + decay
        self.scoring = TrustScoring()

        # ---- SDN state ----
        self.datapaths = {}      # dpid -> datapath object (connected switches)
        self.mac_to_port = {}    # dpid -> {mac -> port} (L2 learning table)

        # ---- statistics for the research evaluation ----
        self.request_count = 0       # total northbound requests seen
        self.allow_count = 0         # requests that passed ZT
        self.deny_count = 0          # requests blocked by ZT
        self.latency_samples = []    # verification latency per request (ms)

        # ---- register the REST controller (northbound API) ----
        wsgi = kwargs['wsgi']
        wsgi.register(ZeroTrustRestController, {'zt_app': self})

        logger.info("Zero Trust RYU Controller started on OpenFlow port 6653")

    # =====================================================================
    # OPENFLOW EVENTS (southbound, between controller and switch)
    # =====================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Called when a switch connects. Register it and install the
        table-miss flow so that unknown packets are sent to the controller."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {})
        logger.info("Switch %016x connected", dpid)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule: never drop a packet we don't know about,
        # send it to the controller instead (priority 0 default entry).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Simple L2 learning switch logic so that the emulated hosts
        (h1..h4) can actually communicate with each other (ping/iperf)."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)
        if not eth:
            return
        eth = eth[0]

        # Ignore LLDP / IPv6 multicast noise so the learning table
        # stays clean.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port[dpid][src] = in_port   # LEARN: src mac is on in_port

        # If we already know where the destination lives -> install a
        # normal flow rule; otherwise flood the packet.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=1,
                                    match=match,
                                    instructions=inst)
            datapath.send_msg(mod)
            out_actions = [parser.OFPActionOutput(out_port)]
        else:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            out_actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=out_actions,
                                  data=msg.data)
        datapath.send_msg(out)

    # =====================================================================
    # ZERO TRUST NORTHBOUND HANDLING (called by the REST API)
    # =====================================================================

    def handle_northbound_request(self, body):
        """
        Every application request arrives here through the REST API.
        This is the main Zero Trust enforcement point:

        1. Time the request (for latency measurement)
        2. Run the 7-layer verification pipeline (PEP -> engine -> policy)
        3. If ALLOWED: apply the requested OpenFlow action to the switch
        4. If DENIED:  do not touch the switch; report 403
        5. Update continuous trust score + statistics

        Returns (verdict_dict, latency_ms)
        """
        request_data = dict(body)
        app_id = request_data.get('app_id', 'unknown')
        t0 = time.time()

        # --- full pipeline: PEP internally calls trust verification
        #     engine and policy engine, then enforces the decision ---
        verdict = self.pep.enforce(app_id, request_data)

        latency_ms = (time.time() - t0) * 1000.0
        allowed = (verdict.get('action') == 'allow')

        # --- update continuous trust scoring (hybrid trust model) ---
        #  session trust = per-request verdict from the 7-layer engine
        #  reputation   = long-term score kept by the scoring module
        #  composite    = 0.7*session + 0.3*reputation
        self.scoring.update_score(app_id, {
            'allowed': allowed,
            'reason': verdict.get('reason', '')
        })
        session_trust = float(verdict.get('trust_score', 0.0))
        reputation = self.scoring.scores.get(app_id, 0.5)
        composite_trust = round(0.7 * session_trust + 0.3 * reputation, 2)
        self.trust_engine.trust_scores[app_id] = composite_trust
        verdict['trust_score'] = composite_trust

        # --- statistics ---
        self.request_count += 1
        if allowed:
            self.allow_count += 1
            # apply the requested OpenFlow action (only after ZT approval)
            self._apply_openflow_action(request_data)
        else:
            self.deny_count += 1
        self.latency_samples.append(latency_ms)

        logger.info("[ZT] %s -> %s | action=%s trust=%.2f | %.2f ms",
                    app_id,
                    'ALLOWED' if allowed else 'DENIED',
                    request_data.get('action', '?'),
                    verdict.get('trust_score', 0.0),
                    latency_ms)

        return verdict, latency_ms

    def _apply_openflow_action(self, request_data):
        """
        Translate an approved northbound request into a real OpenFlow
        flow modification message sent to the connected switch(es).

        Supported operations (op field):
          - install_flow: install a forwarding rule (match + out_port)
          - drop_flow:    install a DROP rule for the given match
        """
        if not self.datapaths:
            logger.warning("No switches connected - cannot apply flow")
            return False
        # take the first connected switch (single-switch topology)
        datapath = next(iter(self.datapaths.values()))
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        op = request_data.get('op', 'install_flow')
        match_dict = request_data.get('match', {})
        out_port = int(request_data.get('out_port', ofproto.OFPP_FLOOD))

        # Build an OpenFlow match from the JSON match dictionary.
        # Supported keys: eth_dst, eth_src, ipv4_dst, ipv4_src
        match_args = {}
        if 'eth_dst' in match_dict:
            match_args['eth_dst'] = match_dict['eth_dst']
        if 'eth_src' in match_dict:
            match_args['eth_src'] = match_dict['eth_src']
        if 'ipv4_dst' in match_dict:
            match_args['ipv4_dst'] = match_dict['ipv4_dst']
        if 'ipv4_src' in match_dict:
            match_args['ipv4_src'] = match_dict['ipv4_src']
        match = parser.OFPMatch(**match_args)

        if op == 'drop_flow':
            # DROP rule: empty action list inside APPLY_ACTIONS == drop
            actions = []
            priority = 100  # high priority so it beats forwarding rules
            logger.info("[ZT] Installing DROP flow: %s", match_args)
        else:
            # forwarding rule
            actions = [parser.OFPActionOutput(out_port)]
            priority = 10
            logger.info("[ZT] Installing FORWARD flow: %s -> port %d",
                        match_args, out_port)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(mod)
        return True

    def get_stats(self):
        """Return evaluation statistics for the REST monitor endpoint."""
        avg_lat = (sum(self.latency_samples) / len(self.latency_samples)
                   if self.latency_samples else 0.0)
        return {
            'total_requests': self.request_count,
            'allowed': self.allow_count,
            'denied': self.deny_count,
            'block_rate': (self.deny_count / max(1, self.request_count)) * 100,
            'avg_verification_latency_ms': round(avg_lat, 3),
            'trust_scores': dict(self.trust_engine.trust_scores),
            'connected_switches': list(self.datapaths.keys())
        }


class ZeroTrustRestController(ControllerBase):
    """
    REST (northbound) API exposed by the controller.
    Network applications talk to the controller through these routes,
    and EVERY request is forced through the Zero Trust pipeline.
    """

    def __init__(self, req, link, data, **config):
        super(ZeroTrustRestController, self).__init__(req, link, data, **config)
        # data contains {'zt_app': <ZeroTrustController instance>}
        self.zt_app = data['zt_app']

    @route('zerotrust', '/zt/register', methods=['POST'])
    def zt_register(self, req, **kwargs):
        """
        ONE-TIME registration of a network application.
        Body: {app_id, api_key, role, device_id, device_fingerprint, hostname}
        Returns: {status, app_id, token, timestamp, expires_in}
        The token is generated here (server side) and used by the app
        with every subsequent request.
        """
        try:
            body = json.loads(req.body)
        except Exception:
            return Response(status=400, body='{"error":"invalid JSON"}')
        app_id = body.get('app_id')
        if not app_id:
            return Response(status=400, body='{"error":"app_id required"}')

        self.zt_app.trust_engine.register_application(
            app_id,
            body.get('api_key', ''),
            body.get('role', 'guest_app'),
            {'device_id': body.get('device_id', ''),
             'device_fingerprint': body.get('device_fingerprint', ''),
             'hostname': body.get('hostname', '')})
        # start with the neutral trust score and track it
        self.zt_app.scoring.initialize_score(app_id)

        token_data = self.zt_app.trust_engine.generate_token(app_id)
        resp = {'status': 'registered', 'app_id': app_id}
        resp.update(token_data)   # token, timestamp, expires_in
        return Response(content_type='application/json', status=200,
                        body=json.dumps(resp))

    @route('zerotrust', '/zt/request', methods=['POST'])
    def zt_request(self, req, **kwargs):
        """
        EVERY application request goes through this endpoint.
        If it passes the whole Zero Trust pipeline and a policy allows it,
        the controller applies the requested OpenFlow action.
        Otherwise HTTP 403 is returned and the switch is untouched.
        """
        try:
            body = json.loads(req.body)
        except Exception:
            return Response(status=400, body='{"error":"invalid JSON"}')

        verdict, latency = self.zt_app.handle_northbound_request(body)
        payload = {
            'allowed': verdict.get('action') == 'allow',
            'trust_score': verdict.get('trust_score', 0.0),
            'reason': verdict.get('reason', ''),
            'latency_ms': round(latency, 3)
        }
        status = 200 if payload['allowed'] else 403
        return Response(content_type='application/json', status=status,
                        body=json.dumps(payload))

    @route('zerotrust', '/zt/trust/{app_id}', methods=['GET'])
    def zt_trust(self, req, **kwargs):
        """Check the current trust score of an application."""
        app_id = kwargs['app_id']
        score = self.zt_app.trust_engine.get_trust_score(app_id)
        return Response(content_type='application/json', status=200,
                        body=json.dumps({'app_id': app_id,
                                         'trust_score': score}))

    @route('zerotrust', '/zt/stats', methods=['GET'])
    def zt_stats(self, req, **kwargs):
        """Get evaluation statistics (used for measurements/paper)."""
        return Response(content_type='application/json', status=200,
                        body=json.dumps(self.zt_app.get_stats()))