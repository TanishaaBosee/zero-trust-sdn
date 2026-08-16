"""
baseline_controller.py - Baseline (non-Zero-Trust) RYU controller
====================================================================
Used ONLY as the experimental control for the IEEE evaluation:

- Identical L2 learning-switch datapath logic (same forwarding engine)
- Identical REST northbound API surface (/baseline/request)
- NO trust verification, NO policy engine, NO PEP:
  every northbound request is forwarded to OpenFlow immediately.

By comparing /baseline/request latency against /zt/request latency we
quantify the overhead of the Zero Trust pipeline.
"""

import json
import time
import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, Response, route

LOG = logging.getLogger("BaselineController")


class BaselineController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(BaselineController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.request_count = 0
        self.latency_samples = []
        wsgi = kwargs['wsgi']
        wsgi.register(ZeroTrustRestController, {'baseline_app': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 128)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        src, dst = msg.match['eth_src'], msg.match['eth_dst']
        in_port = msg.match['in_port']
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, priority=1, match=match,
                instructions=inst))
            out_actions = actions
        else:
            out_actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=out_actions, data=msg.data))

    def handle_northbound_request(self, body):
        """Baseline path: immediate allow, no verification."""
        t0 = time.time()
        self.request_count += 1
        latency_ms = (time.time() - t0) * 1000.0
        self.latency_samples.append(latency_ms)
        return {
            'allowed': True,
            'trust_score': 1.0,
            'reason': 'Baseline control: no Zero Trust verification'
        }, latency_ms

    def apply_flow(self, request_data):
        if not self.datapaths:
            return False
        datapath = next(iter(self.datapaths.values()))
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match_args = {}
        for key in ('eth_dst', 'eth_src', 'ipv4_dst', 'ipv4_src'):
            if key in request_data.get('match', {}):
                match_args[key] = request_data['match'][key]
        match = parser.OFPMatch(**match_args)
        op = request_data.get('op', 'install_flow')
        if op == 'drop_flow':
            actions, priority = [], 100
        else:
            actions = [parser.OFPActionOutput(
                int(request_data.get('out_port', ofproto.OFPP_FLOOD)))]
            priority = 10
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, buffer_id=ofproto.OFP_NO_BUFFER))
        return True

    def get_stats(self):
        avg_lat = (sum(self.latency_samples) / len(self.latency_samples)
                   if self.latency_samples else 0.0)
        return {
            'total_requests': self.request_count,
            'avg_verification_latency_ms': round(avg_lat, 3),
            'connected_switches': list(self.datapaths.keys())
        }


class ZeroTrustRestController(ControllerBase):
    """REST northbound API exposing the BASELINE request path."""

    def __init__(self, req, link, data, **config):
        super(ZeroTrustRestController, self).__init__(req, link, data,
                                                      **config)
        self.baseline_app = data['baseline_app']

    @route('baseline', '/baseline/request', methods=['POST'])
    def baseline_request(self, req, **kwargs):
        try:
            body = json.loads(req.body)
        except Exception:
            return Response(status=400, body='{"error":"invalid JSON"}')
        verdict, latency = self.baseline_app.handle_northbound_request(body)
        if verdict.get('allowed'):
            self.baseline_app.apply_flow(body)
        payload = {
            'allowed': verdict.get('allowed'),
            'trust_score': verdict.get('trust_score', 1.0),
            'reason': verdict.get('reason', ''),
            'latency_ms': round(latency, 3)
        }
        return Response(content_type='application/json', status=200,
                        body=json.dumps(payload))

    @route('baseline', '/baseline/stats', methods=['GET'])
    def baseline_stats(self, req, **kwargs):
        return Response(content_type='application/json', status=200,
                        body=json.dumps(self.baseline_app.get_stats()))