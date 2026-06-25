from pox.lib.addresses import IPAddr

NAT_PORT_MIN = 40000
NAT_PORT_MAX = 60000


class NatEngine(object):
    def __init__(self, public_ip):
        self.public_ip = IPAddr(public_ip)
        self.nat_in = {}
        self.nat_out = {}
        self.used_nat_ports = set()
        self.next_nat_port = NAT_PORT_MIN

    # Asigna un puerto NAT disponible para el protocolo especificado
    def allocate_port(self, protocol):
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

    # Obtiene o crea una traducción de salida para el paquete
    def get_or_create_outbound(
        self, protocol, src_ip, src_port, dst_ip, dst_port, src_mac, switch_port
    ):
        private_key = (protocol, src_ip, src_port, dst_ip, dst_port)
        translation = self.nat_out.get(private_key)

        if translation is None:
            nat_port = self.allocate_port(protocol)
            if nat_port is None:
                return None

            translation = {
                "protocol": protocol,
                "private_ip": IPAddr(src_ip),
                "private_port": src_port,
                "private_mac": src_mac,
                "private_switch_port": switch_port,
                "public_ip": self.public_ip,
                "nat_port": nat_port,
                "remote_ip": IPAddr(dst_ip),
                "remote_port": dst_port,
            }

            public_key = (protocol, dst_ip, dst_port, self.public_ip, nat_port)
            self.nat_out[private_key] = translation
            self.nat_in[public_key] = translation

        return translation

    # Obtiene la traducción de entrada para el paquete
    def get_inbound(self, protocol, src_ip, src_port, dst_ip, dst_port):
        public_key = (protocol, src_ip, src_port, dst_ip, dst_port)
        return self.nat_in.get(public_key)

    def release_translation(self, match):
        """Libera los puertos basados en la regla OpenFlow que expiró"""
        keys_to_delete = []
        port_to_free = None
        protocol_to_free = None
        expired_translation = None

        for key, trans in list(self.nat_out.items()):
            if (
                trans["private_ip"] == match.nw_src
                and trans["private_port"] == match.tp_src
                and trans["protocol"] == match.nw_proto
            ) or (
                trans["public_ip"] == match.nw_dst
                and trans["nat_port"] == match.tp_dst
                and trans["protocol"] == match.nw_proto
            ):
                keys_to_delete.append(key)
                port_to_free = trans["nat_port"]
                protocol_to_free = trans["protocol"]
                expired_translation = trans
                break

        if keys_to_delete:
            for key in keys_to_delete:
                trans = self.nat_out[key]
                public_key = (
                    trans["protocol"],
                    trans["remote_ip"],
                    trans["remote_port"],
                    trans["public_ip"],
                    trans["nat_port"],
                )
                del self.nat_out[key]
                self.nat_in.pop(public_key, None)

                port_key = (protocol_to_free, port_to_free)
                if port_key in self.used_nat_ports:
                    self.used_nat_ports.remove(port_key)

            return expired_translation
        return None
