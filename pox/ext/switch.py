import pox.openflow.libopenflow_01 as of


class L2Switch(object):
    def __init__(self, connection, public_port):
        self.connection = connection
        self.public_port = public_port
        self.mac_to_port = {}

    def handle_internal_traffic(self, event, packet):
        # Aprender MAC origen
        self.mac_to_port[packet.src] = event.port

        # Despachar
        if packet.dst in self.mac_to_port and not packet.dst.is_multicast:
            out_port = self.mac_to_port[packet.dst]
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(msg)
        else:
            self.flood_private(event)

    def flood_private(self, event):
        msg = of.ofp_packet_out(data=event.ofp.data)
        for port in self.connection.ports:
            if port != event.port and port != self.public_port:
                msg.actions.append(of.ofp_action_output(port=port))

        if len(msg.actions) > 0:
            self.connection.send(msg)
