from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

class FirewallApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Define blocked rules: (src_ip, dst_ip, protocol, port)
        self.blocked_rules = [
            ('10.0.0.1', '10.0.0.3', 'tcp', 80),   # Block h1→h3 HTTP
            (None, None, 'tcp', 23),               # Block Telnet everywhere
            ('10.0.0.2', '10.0.0.4', 'tcp', 22)    # Block SSH ONLY h2→h4
        ]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle,
            hard_timeout=hard,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def is_blocked(self, src_ip, dst_ip, proto, port):
        for rule in self.blocked_rules:
            r_src, r_dst, r_proto, r_port = rule
            if (r_src is None or r_src == src_ip) and \
               (r_dst is None or r_dst == dst_ip) and \
               r_proto == proto and r_port == port:
                return True
        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # --- Firewall logic ---
        if ip_pkt:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            proto, port = None, None
            if tcp_pkt:
                proto, port = 'tcp', tcp_pkt.dst_port
            elif udp_pkt:
                proto, port = 'udp', udp_pkt.dst_port

            if proto and self.is_blocked(ip_pkt.src, ip_pkt.dst, proto, port):
                self.logger.info("BLOCKED: %s → %s %s:%d",
                                 ip_pkt.src, ip_pkt.dst, proto, port)

                
                if proto == 'tcp':
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=6,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        tcp_dst=port
                    )
                else:
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=17,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        udp_dst=port
                    )

                self.add_flow(datapath, 100, match, [])
                return  # DROP

        # --- Normal switching ---
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
