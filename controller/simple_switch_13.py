"""
simple_switch_13.py  —  Learning switch with built-in Snort block listener
===========================================================================
Priority ladder:
  200  DROP  (installed by _block_listener thread reading /tmp/block_pipe)
    1  FORWARD (learned unicast flows)
    0  TABLE-MISS → CONTROLLER

block_agent writes "BLOCK <ip>\n" lines to the named pipe /tmp/block_pipe.
A background thread in this app reads them and installs DROP flows directly
via OpenFlow — no REST API needed.
"""

import os
import threading

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types

PIPE_PATH      = "/tmp/block_pipe"
BLOCK_PRIORITY = 200


class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}        # {dpid: {mac: port}}
        self.datapaths   = {}        # {dpid: datapath}
        self.blocked_ips = set()

        # Create named pipe and start listener thread
        self._setup_pipe()
        t = threading.Thread(target=self._block_listener, daemon=True)
        t.start()

    # ── Named pipe setup ──────────────────────────────────────────────────────

    def _setup_pipe(self):
        if os.path.exists(PIPE_PATH):
            os.remove(PIPE_PATH)
        os.mkfifo(PIPE_PATH)
        self.logger.info("[blocker] Named pipe ready at %s", PIPE_PATH)

    # ── Background thread: read BLOCK commands from pipe ──────────────────────

    def _block_listener(self):
        self.logger.info("[blocker] Waiting for block commands on %s", PIPE_PATH)
        while True:
            # open() blocks until block_agent opens the write end
            with open(PIPE_PATH, "r") as pipe:
                for line in pipe:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) == 2 and parts[0] == "BLOCK":
                        src_ip = parts[1]
                        self._install_block(src_ip)
                    elif len(parts) == 2 and parts[0] == "UNBLOCK":
                        src_ip = parts[1]
                        self._remove_block(src_ip)

    def _install_block(self, src_ip):
        if src_ip in self.blocked_ips:
            return
        self.logger.warning("[blocker] Installing DROP for %s on all switches", src_ip)
        for dpid, datapath in self.datapaths.items():
            parser  = datapath.ofproto_parser
            match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self._add_flow(datapath, priority=BLOCK_PRIORITY, match=match, actions=[])
            self.logger.info("[blocker] DROP flow installed on dpid=0x%016x for %s", dpid, src_ip)
        self.blocked_ips.add(src_ip)

    def _remove_block(self, src_ip):
        if src_ip not in self.blocked_ips:
            return
        self.logger.info("[blocker] Removing DROP for %s", src_ip)
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser  = datapath.ofproto_parser
            match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE_STRICT,
                priority=BLOCK_PRIORITY,
                match=match,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
            )
            datapath.send_msg(mod)
        self.blocked_ips.discard(src_ip)

    # ── Handshake: install table-miss flow ────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath   # register for blocking

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Switch 0x%016x connected — table-miss installed", datapath.id)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod     = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
        )
        datapath.send_msg(mod)

    # ── Packet-in: MAC learning + unicast forwarding ──────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst  = eth.dst
        src  = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=10)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)
