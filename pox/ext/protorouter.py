# Import some POX stuff
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK = 24

PRIVATE_IP = IPAddr("192.168.1.254")
PUBLIC_IP = IPAddr("200.0.0.254")
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")

PUBLIC_PORT = 1

NAT_PORT_MIN = 40000
NAT_PORT_MAX = 60000

H1_MAC = EthAddr("00:00:00:00:00:01")  # TODO: resolver mediante ARP.


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        self.nat_in = {}
        self.nat_out = {}
        self.used_nat_ports = set()
        self.next_nat_port = NAT_PORT_MIN
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. "
                "POX no pudo decodificar el paquete."
            )
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        elif event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        else:
            log_color(YELLOW, "Paquete ignorado: protocolo distinto de IPv4/ARP.")

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW,
            f"RECIBIDO: {ip_pkt.srcip} -> {ip_pkt.dstip} | "
            f"MAC: {packet.src} -> {packet.dst} | In Port: {in_port}",
        )

        transport_pkt = ip_pkt.payload
        if not hasattr(transport_pkt, "srcport") or not hasattr(
            transport_pkt, "dstport"
        ):
            log_color(RED, "DROP: protocolo de transporte no soportado por el NAT")
            return

        if in_port == PUBLIC_PORT:
            self.handle_incoming_ip(event, ip_pkt, transport_pkt)
        else:
            self.handle_outgoing_ip(event, packet, ip_pkt, transport_pkt)

    def handle_incoming_ip(self, event, ip_pkt, transport_pkt):
        if ip_pkt.dstip != PUBLIC_IP:
            log_color(RED, f"DROP: paquete publico dirigido a {ip_pkt.dstip}")
            return

        public_key = (
            ip_pkt.protocol,
            ip_pkt.srcip,
            transport_pkt.srcport,
            ip_pkt.dstip,
            transport_pkt.dstport,
        )

        translation = self.nat_in.get(public_key)

        if translation is None:
            log_color(RED, f"DROP: no existe traduccion para {public_key}")
            return

        self.install_incoming_flow(translation, event.ofp)

        log_color(
            GREEN,
            f"NAT ENTRANTE: {PUBLIC_IP}:{translation['nat_port']} -> "
            f"{translation['private_ip']}:{translation['private_port']}",
        )

    def handle_outgoing_ip(self, event, packet, ip_pkt, transport_pkt):
        if not ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(
                RED,
                f"DROP: {ip_pkt.srcip} no pertenece a "
                f"{PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )
            return

        private_key = (
            ip_pkt.protocol,
            ip_pkt.srcip,
            transport_pkt.srcport,
            ip_pkt.dstip,
            transport_pkt.dstport,
        )

        translation = self.nat_out.get(private_key)

        if translation is None:
            nat_port = self.allocate_nat_port(ip_pkt.protocol)
            if nat_port is None:
                log_color(RED, "DROP: no quedan puertos NAT disponibles")
                return

            translation = {
                "protocol": ip_pkt.protocol,
                "private_ip": ip_pkt.srcip,
                "private_port": transport_pkt.srcport,
                "private_mac": packet.src,
                "private_switch_port": event.port,
                "public_ip": PUBLIC_IP,
                "nat_port": nat_port,
                "remote_ip": ip_pkt.dstip,
                "remote_port": transport_pkt.dstport,
            }

            public_key = (
                ip_pkt.protocol,
                ip_pkt.dstip,
                transport_pkt.dstport,
                PUBLIC_IP,
                nat_port,
            )

            self.nat_out[private_key] = translation
            self.nat_in[public_key] = translation

            log_color(
                GREEN,
                f"NUEVA TRADUCCION: {ip_pkt.srcip}:{transport_pkt.srcport} -> "
                f"{PUBLIC_IP}:{nat_port}",
            )

        # Se instalan ambos sentidos cuando se crea o recupera la traduccion.
        self.install_incoming_flow(translation)
        self.install_outgoing_flow(translation, event.ofp)

        log_color(
            GREEN,
            f"NAT SALIENTE: {translation['private_ip']}:"
            f"{translation['private_port']} -> "
            f"{PUBLIC_IP}:{translation['nat_port']}",
        )

    def allocate_nat_port(self, protocol):
        port_count = NAT_PORT_MAX - NAT_PORT_MIN + 1

        for _ in range(port_count):
            nat_port = self.next_nat_port
            self.next_nat_port += 1

            if self.next_nat_port > NAT_PORT_MAX:
                self.next_nat_port = NAT_PORT_MIN

            port_key = (protocol, nat_port)
            if port_key not in self.used_nat_ports:
                self.used_nat_ports.add(port_key)
                return nat_port

        return None

    def install_incoming_flow(self, translation, packet_in=None):
        fm_in = of.ofp_flow_mod()
        fm_in.idle_timeout = 30
        fm_in.match.in_port = PUBLIC_PORT
        fm_in.match.dl_type = ethernet.IP_TYPE
        fm_in.match.nw_proto = translation["protocol"]
        fm_in.match.nw_src = translation["remote_ip"]
        fm_in.match.nw_dst = translation["public_ip"]
        fm_in.match.tp_src = translation["remote_port"]
        fm_in.match.tp_dst = translation["nat_port"]

        fm_in.actions.append(
            of.ofp_action_nw_addr.set_dst(translation["private_ip"])
        )
        fm_in.actions.append(
            of.ofp_action_tp_port.set_dst(translation["private_port"])
        )
        fm_in.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_in.actions.append(
            of.ofp_action_dl_addr.set_dst(translation["private_mac"])
        )
        fm_in.actions.append(
            of.ofp_action_output(port=translation["private_switch_port"])
        )

        if packet_in is not None:
            fm_in.data = packet_in

        self.connection.send(fm_in)

    def install_outgoing_flow(self, translation, packet_in=None):
        fm_out = of.ofp_flow_mod()
        fm_out.idle_timeout = 30
        fm_out.match.in_port = translation["private_switch_port"]
        fm_out.match.dl_type = ethernet.IP_TYPE
        fm_out.match.nw_proto = translation["protocol"]
        fm_out.match.nw_src = translation["private_ip"]
        fm_out.match.nw_dst = translation["remote_ip"]
        fm_out.match.tp_src = translation["private_port"]
        fm_out.match.tp_dst = translation["remote_port"]

        fm_out.actions.append(
            of.ofp_action_nw_addr.set_src(translation["public_ip"])
        )
        fm_out.actions.append(
            of.ofp_action_tp_port.set_src(translation["nat_port"])
        )
        fm_out.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm_out.actions.append(of.ofp_action_dl_addr.set_dst(H1_MAC))
        fm_out.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

        if packet_in is not None:
            fm_out.data = packet_in

        self.connection.send(fm_out)

    def handle_arp(self, event):
        red_packet = event.parsed
        arp_packet = red_packet.payload

        if (
            arp_packet.opcode == arp.REQUEST
            and arp_packet.protodst in (PRIVATE_IP, PUBLIC_IP)
        ):
            reply_mac = (
                PRIVATE_MAC if arp_packet.protodst == PRIVATE_IP else PUBLIC_MAC
            )
            reply_ip = (
                PRIVATE_IP if arp_packet.protodst == PRIVATE_IP else PUBLIC_IP
            )

            arp_response = arp()
            arp_response.opcode = arp.REPLY

            arp_response.hwsrc = reply_mac
            arp_response.protosrc = reply_ip

            arp_response.hwdst = arp_packet.hwsrc
            arp_response.protodst = arp_packet.protosrc

            ethernet_response = ethernet()
            ethernet_response.type = ethernet.ARP_TYPE
            ethernet_response.src = reply_mac
            ethernet_response.dst = arp_packet.hwsrc
            ethernet_response.payload = arp_response

            msg = of.ofp_packet_out()
            msg.data = ethernet_response.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))

            self.connection.send(msg)
            log_color(GREEN, f"ARP REPLY: {reply_ip} esta en {reply_mac}")


def launch():
    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
