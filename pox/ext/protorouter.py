# Import some POX stuff
import pox.openflow.libopenflow_01 as of  # OpenFlow 1.0 library
from pox.core import core  # Main POX object
from pox.lib.addresses import EthAddr, IPAddr  # Address types
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


PRIVATE_SUBNET = IPAddr("192.168.1.0")  # Red interna
PRIVATE_MASK = 24  # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")  # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")  # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")  # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1  # Puerto del switch conectado a la red pública

H1_MAC = EthAddr(
    "00:00:00:00:00:01"
)  # MAC del host externo (TODO: resolver mediante ARP)


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}
        self.waiting_packets = {}
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete."
            )
            return

        if event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4.")

    def send_arp_request(self, target_ip, out_port, router_ip, router_mac):
        log_color(CYAN, f"[ARP] Enviando REQUEST buscando la MAC de {target_ip}")

        # Construimos la consulta ARP
        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        arp_req.protodst = target_ip
        arp_req.hwsrc = router_mac
        arp_req.protosrc = router_ip
        arp_req.hwtype = arp.HW_TYPE_ETHERNET
        arp_req.prototype = arp.PROTO_TYPE_IP
        arp_req.hwlen = 6
        arp_req.protolen = 4

        # Lo metemos en una trama Ethernet
        eth_req = ethernet(
            type=ethernet.ARP_TYPE, src=router_mac, dst=EthAddr("ff:ff:ff:ff:ff:ff")
        )
        eth_req.payload = arp_req

        # Lo enviamos al switch
        msg = of.ofp_packet_out()
        msg.data = eth_req.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW,
            f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}",
        )

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            target_ip = ip_pkt.dstip

            # 1. VERIFICACIÓN DE MAC: ¿Conocemos el destino?
            if target_ip not in self.arp_table:
                log_color(
                    YELLOW,
                    f"[BUFFER] MAC desconocida para {target_ip}. Encolando paquete...",
                )

                # Preparamos la cola si es la primera vez que buscamos esta IP
                if target_ip not in self.waiting_packets:
                    self.waiting_packets[target_ip] = []

                # Guardamos el evento original para procesarlo después
                self.waiting_packets[target_ip].append((event, PUBLIC_PORT, PUBLIC_MAC))

                # Disparamos el ARP Request para averiguar la MAC
                self.send_arp_request(target_ip, PUBLIC_PORT, PUBLIC_IP, PUBLIC_MAC)

                # Frenamos la ejecución acá. Se reanudará cuando llegue el ARP Reply.
                return

            # 2. DESPACHO: Si llegamos acá, la MAC ya está en la tabla (chau H1_MAC)
            target_mac = self.arp_table[target_ip]

            log_color(
                GREEN,
                f"MATCH: {ip_pkt.srcip} pertenece a la red privada. Despachando hacia {target_mac}",
            )

            # Instalar Flujo Saliente
            fm = of.ofp_flow_mod()
            fm.idle_timeout = 10
            fm.match.nw_src = ip_pkt.srcip
            fm.match.dl_type = 0x800  # IPv4
            fm.match.in_port = in_port

            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(target_mac))  # MAC Dinámica
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(fm)

            # Instalar Flujo Entrante (para respuesta)
            fm_back = of.ofp_flow_mod()
            fm_back.idle_timeout = 10
            fm_back.match.nw_src = ip_pkt.dstip
            fm_back.match.nw_dst = ip_pkt.srcip
            fm_back.match.dl_type = 0x800  # IPv4
            fm_back.match.in_port = PUBLIC_PORT

            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(fm_back)

            # Reenviar paquete actual con MACs actualizadas
            packet.src = PUBLIC_MAC
            packet.dst = target_mac  # MAC Dinámica
            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            log_color(
                CYAN,
                f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {PUBLIC_MAC} → {target_mac} | Out Port: {PUBLIC_PORT}",
            )
            self.connection.send(msg)

        else:
            log_color(
                RED,
                f"NO MATCH: Tráfico no manejado desde {ip_pkt.srcip}",
            )

    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        # 1. APRENDIZAJE PRIMERO: Guardamos la MAC en la tabla
        if arp_pkt.protosrc not in self.arp_table:
            log_color(
                CYAN, f"[ARP] Aprendiendo MAC: {arp_pkt.protosrc} -> {arp_pkt.hwsrc}"
            )
        self.arp_table[arp_pkt.protosrc] = arp_pkt.hwsrc

        # 2. DESPACHO DEL BUFFER: Ahora sí, liberamos los paquetes (handle_ip ya encontrará la MAC)
        if arp_pkt.protosrc in self.waiting_packets:
            log_color(
                GREEN, f"[BUFFER] Liberando paquetes en espera para {arp_pkt.protosrc}"
            )
            for pending_event, out_port, router_mac in self.waiting_packets[
                arp_pkt.protosrc
            ]:
                self.handle_ip(pending_event)
            del self.waiting_packets[arp_pkt.protosrc]

        # 3. PROCESAMIENTO: Si es una solicitud (REQUEST), evaluamos si debemos responder
        if arp_pkt.opcode == arp.REQUEST:
            reply_mac = None

            # Verificamos si consultan por la IP pública del router (desde el exterior)
            if arp_pkt.protodst == PUBLIC_IP and in_port == PUBLIC_PORT:
                reply_mac = PUBLIC_MAC

            # Verificamos si consultan por la IP privada del router (desde la red interna)
            elif arp_pkt.protodst == PRIVATE_IP and in_port != PUBLIC_PORT:
                reply_mac = PRIVATE_MAC

            # Si la consulta era para nuestras interfaces, armamos el paquete de respuesta
            if reply_mac:
                log_color(
                    GREEN,
                    f"[ARP] Respondiendo a {arp_pkt.protosrc}: {arp_pkt.protodst} es {reply_mac}",
                )

                # Construimos la capa ARP (Reply)
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwdst = arp_pkt.hwsrc
                arp_reply.protodst = arp_pkt.protosrc
                arp_reply.hwsrc = reply_mac
                arp_reply.protosrc = arp_pkt.protodst
                arp_reply.hwtype = arp_pkt.hwtype
                arp_reply.prototype = arp_pkt.prototype
                arp_reply.hwlen = arp_pkt.hwlen
                arp_reply.protolen = arp_pkt.protolen

                # Encapsulamos el ARP en una nueva trama Ethernet
                eth_reply = ethernet(type=packet.type, src=reply_mac, dst=packet.src)
                eth_reply.payload = arp_reply

                # Instruimos al switch para que devuelva el paquete por el mismo puerto
                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
