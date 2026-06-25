# protorouter.py
import pox.openflow.libopenflow_01 as of
from nat import NatEngine
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from switch import L2Switch

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


# Constantes de Red
PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK = 24
PRIVATE_IP = IPAddr("192.168.1.254")
PUBLIC_IP = IPAddr("200.0.0.254")
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")
PUBLIC_PORT = 1


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection

        # 1. Instanciamos nuestros módulos segregados
        self.nat = NatEngine(PUBLIC_IP)
        self.switch = L2Switch(connection, PUBLIC_PORT)

        self.public_arp = {}
        self.pending_packets = {}
        self.arp_requests_in_progress = set()

        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete."
            )
            return

        packet = event.parsed
        if packet.type == ethernet.IP_TYPE:
            self.handle_ip(event, packet)
        elif packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event, packet)
        else:
            log_color(YELLOW, "Paquete ignorado: protocolo distinto de IPv4/ARP.")

    def handle_ip(self, event, packet):
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW,
            f"RECIBIDO: {ip_pkt.srcip} -> {ip_pkt.dstip} | MAC: {packet.src} -> {packet.dst} | In Port: {in_port}",
        )

        # A. Vía Rápida: Switching Interno (Capa 2)
        if in_port != PUBLIC_PORT and ip_pkt.dstip.inNetwork(
            PRIVATE_SUBNET, PRIVATE_MASK
        ):
            self.switch.handle_internal_traffic(event, packet)
            return

        # B. Filtro NAT: Solo TCP/UDP (Capa 4)
        transport_pkt = ip_pkt.payload
        if not hasattr(transport_pkt, "srcport") or not hasattr(
            transport_pkt, "dstport"
        ):
            log_color(
                RED,
                "DROP: Protocolo de transporte no soportado por el NAT (No es TCP/UDP)",
            )
            return

        # C. Ruteo (Capa 3)
        if in_port == PUBLIC_PORT:
            self.process_incoming_nat(event, ip_pkt, transport_pkt)
        else:
            self.process_outgoing_nat(event, packet, ip_pkt, transport_pkt)

    def process_incoming_nat(self, event, ip_pkt, transport_pkt):
        if ip_pkt.dstip != PUBLIC_IP:
            log_color(
                RED, f"DROP: Paquete público dirigido a IP inválida ({ip_pkt.dstip})"
            )
            return

        trans = self.nat.get_inbound(
            ip_pkt.protocol,
            ip_pkt.srcip,
            transport_pkt.srcport,
            ip_pkt.dstip,
            transport_pkt.dstport,
        )
        if trans:
            self.install_nat_flows(trans)
            log_color(
                CYAN,
                f"NAT ENTRANTE: {PUBLIC_IP}:{trans['nat_port']} -> {trans['private_ip']}:{trans['private_port']}",
            )
        else:
            log_color(
                RED,
                f"DROP: No hay traducción activa para el puerto {transport_pkt.dstport}",
            )

    def process_outgoing_nat(self, event, packet, ip_pkt, transport_pkt):
        if not ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(
                RED,
                f"DROP: IP Origen {ip_pkt.srcip} no pertenece a la subred {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )
            return
        if ip_pkt.ttl <= 1:
            log_color(RED, "DROP: Paquete descartado por TTL expirado (<=1)")
            return
        ip_pkt.ttl -= 1

        trans = self.nat.get_or_create_outbound(
            ip_pkt.protocol,
            ip_pkt.srcip,
            transport_pkt.srcport,
            ip_pkt.dstip,
            transport_pkt.dstport,
            packet.src,
            event.port,
        )

        if not trans:
            log_color(RED, "DROP: Puertos NAT agotados (Rango 40000-60000 lleno)")
            return

        remote_mac = self.get_public_mac(trans["remote_ip"])
        if remote_mac is None:
            self.queue_pending_packet(trans["remote_ip"], trans, event.ofp.data)
            log_color(
                YELLOW,
                f"PAQUETE EN ESPERA: Resolviendo MAC para IP destino {trans['remote_ip']}",
            )
            return

        trans["remote_mac"] = remote_mac
        self.install_nat_flows(trans)
        self.send_outgoing_packet(trans, event.ofp.data)
        log_color(
            GREEN,
            f"NAT SALIENTE: {trans['private_ip']}:{trans['private_port']} -> {PUBLIC_IP}:{trans['nat_port']}",
        )

    def get_public_mac(self, target_ip):
        mac = self.public_arp.get(target_ip)
        if mac is None and target_ip not in self.arp_requests_in_progress:
            self.arp_requests_in_progress.add(target_ip)
            self.send_public_arp_request(target_ip)
        return mac

    def queue_pending_packet(self, target_ip, trans, data):
        pending = self.pending_packets.setdefault(target_ip, [])
        pending.append({"translation": trans, "packet_data": data})

    def process_pending_packets(self, target_ip, target_mac):
        pending = self.pending_packets.pop(target_ip, [])
        for item in pending:
            trans = item["translation"]
            trans["remote_mac"] = target_mac
            self.install_nat_flows(trans)
            self.send_outgoing_packet(trans, item["packet_data"])

    def send_outgoing_packet(self, trans, data):
        msg = of.ofp_packet_out(data=data, in_port=trans["private_switch_port"])
        msg.actions.append(of.ofp_action_nw_addr.set_src(trans["public_ip"]))
        msg.actions.append(of.ofp_action_tp_port.set_src(trans["nat_port"]))
        msg.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(trans["remote_mac"]))
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)

    def install_nat_flows(self, trans):
        # Flujo Saliente
        fm_out = of.ofp_flow_mod()
        fm_out.idle_timeout = 30
        fm_out.flags |= of.OFPFF_SEND_FLOW_REM
        fm_out.match.in_port = trans["private_switch_port"]
        fm_out.match.dl_type = ethernet.IP_TYPE
        fm_out.match.nw_proto = trans["protocol"]
        fm_out.match.nw_src = trans["private_ip"]
        fm_out.match.nw_dst = trans["remote_ip"]
        fm_out.match.tp_src = trans["private_port"]
        fm_out.match.tp_dst = trans["remote_port"]

        fm_out.actions.append(of.ofp_action_nw_addr.set_src(trans["public_ip"]))
        fm_out.actions.append(of.ofp_action_tp_port.set_src(trans["nat_port"]))
        fm_out.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm_out.actions.append(of.ofp_action_dl_addr.set_dst(trans["remote_mac"]))
        fm_out.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm_out)

        # Flujo Entrante
        fm_in = of.ofp_flow_mod()
        fm_in.idle_timeout = 30
        fm_in.flags |= of.OFPFF_SEND_FLOW_REM
        fm_in.match.in_port = PUBLIC_PORT
        fm_in.match.dl_type = ethernet.IP_TYPE
        fm_in.match.nw_proto = trans["protocol"]
        fm_in.match.nw_src = trans["remote_ip"]
        fm_in.match.nw_dst = trans["public_ip"]
        fm_in.match.tp_src = trans["remote_port"]
        fm_in.match.tp_dst = trans["nat_port"]

        fm_in.actions.append(of.ofp_action_nw_addr.set_dst(trans["private_ip"]))
        fm_in.actions.append(of.ofp_action_tp_port.set_dst(trans["private_port"]))
        fm_in.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_in.actions.append(of.ofp_action_dl_addr.set_dst(trans["private_mac"]))
        fm_in.actions.append(of.ofp_action_output(port=trans["private_switch_port"]))
        self.connection.send(fm_in)

    def handle_arp(self, event, packet):
        arp_pkt = packet.payload

        if event.port != PUBLIC_PORT and arp_pkt.protodst.inNetwork(
            PRIVATE_SUBNET, PRIVATE_MASK
        ):
            if arp_pkt.protodst != PRIVATE_IP:
                self.switch.handle_internal_traffic(event, packet)
                return

        if arp_pkt.opcode == arp.REQUEST and arp_pkt.protodst in (
            PRIVATE_IP,
            PUBLIC_IP,
        ):
            reply_mac = PRIVATE_MAC if arp_pkt.protodst == PRIVATE_IP else PUBLIC_MAC
            reply_ip = PRIVATE_IP if arp_pkt.protodst == PRIVATE_IP else PUBLIC_IP

            arp_response = arp()
            arp_response.opcode = arp.REPLY
            arp_response.hwsrc = reply_mac
            arp_response.protosrc = reply_ip
            arp_response.hwdst = arp_pkt.hwsrc
            arp_response.protodst = arp_pkt.protosrc

            eth_reply = ethernet(type=ethernet.ARP_TYPE, src=reply_mac, dst=packet.src)
            eth_reply.payload = arp_response

            msg = of.ofp_packet_out(data=eth_reply.pack())
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)
            log_color(
                GREEN,
                f"ARP REPLY: Respondiendo con MAC {reply_mac} para la IP {reply_ip}",
            )

        elif (
            arp_pkt.opcode == arp.REPLY
            and event.port == PUBLIC_PORT
            and arp_pkt.protodst == PUBLIC_IP
        ):
            target_ip = arp_pkt.protosrc
            target_mac = arp_pkt.hwsrc
            self.public_arp[target_ip] = target_mac
            self.arp_requests_in_progress.discard(target_ip)

            log_color(
                GREEN,
                f"ARP APRENDIDO: Servidor público {target_ip} está en MAC {target_mac}",
            )
            self.process_pending_packets(target_ip, target_mac)

    def send_public_arp_request(self, target_ip):
        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.hwsrc = PUBLIC_MAC
        arp_req.hwdst = EthAddr("00:00:00:00:00:00")
        arp_req.protosrc = PUBLIC_IP
        arp_req.protodst = target_ip

        eth_req = ethernet(
            type=ethernet.ARP_TYPE, src=PUBLIC_MAC, dst=EthAddr("ff:ff:ff:ff:ff:ff")
        )
        eth_req.payload = arp_req

        msg = of.ofp_packet_out(data=eth_req.pack())
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)
        log_color(YELLOW, f"ARP REQUEST PÚBLICO: ¿Quién tiene la IP {target_ip}?")

    def _handle_flow_removal(self, event):
        if event.ofp.reason != of.OFPRR_IDLE_TIMEOUT:
            return
        trans = self.nat.release_translation(event.ofp.match)
        if trans:
            log_color(
                YELLOW,
                f"TIMEOUT: Conexión {trans['private_ip']}:{trans['private_port']} expiró por inactividad. Puerto liberado.",
            )


def launch():
    routers = {}

    def start_switch(event):
        log_color(
            YELLOW,
            f"Iniciando ProtoRouter en Switch Datapath ID: {event.connection.dpid}",
        )
        routers[event.connection.dpid] = ProtoRouter(event.connection)

    def handle_flow_removed(event):
        router = routers.get(event.connection.dpid)
        if router:
            router._handle_flow_removal(event)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.openflow.addListenerByName("FlowRemoved", handle_flow_removed)
