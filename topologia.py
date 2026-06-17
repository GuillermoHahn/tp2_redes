#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def my_network():
    # Inicializa la red especificando que el controlador es externo (RemoteController)
    net = Mininet(topo=None, build=False, ipBase="10.0.0.0/8")

    info("*** Agregando el Controlador SDN (POX) ***\n")
    # Por defecto busca en localhost:6633, que es donde correrá POX
    c0 = net.addController(
        name="c0", controller=RemoteController, ip="127.0.0.1", port=6633
    )

    info("*** Agregando el Switch OpenFlow (S1) ***\n")
    # Usamos OVSKernelSwitch que es el estándar para OpenFlow en Mininet
    s1 = net.addSwitch("s1", cls=OVSKernelSwitch, dpid="0000000000000001")

    info("*** Agregando los Hosts ***\n")
    # Servidor Público (h1) - Apunta a la IP de la interfaz pública del switch como gateway
    h1 = net.addHost("h1", ip="200.0.0.1/24", defaultRoute="via 200.0.0.254")

    # Cliente Privado Base (h2) - Apunta a la IP de la interfaz privada del switch como gateway
    h2 = net.addHost("h2", ip="192.168.1.2/24", defaultRoute="via 192.168.1.254")

    info("*** Creando los Enlaces (Links) ***\n")
    # Conectamos h1 a s1.
    # TIP: Forzamos la MAC de h1 según el enunciado para mantener orden, pero el switch aprenderá dinámicamente.
    net.addLink(h1, s1, intfName1="h1-eth0", mac1="00:00:00:00:00:01")

    # Conectamos h2 a s1
    net.addLink(h2, s1, intfName1="h2-eth0", mac2="00:00:00:00:00:02")

    info("*** Iniciando la Red ***\n")
    net.start()

    # Configuración de las MACs específicas de las interfaces de S1 que pide el enunciado
    # (Esto se hace post-start para que las interfaces ya existan en el switch)
    info("*** Configurando direcciones MAC en las interfaces del Switch ***\n")
    s1.cmd(
        "ifconfig s1-eth1 hw ether 00:00:00:aa:aa:aa"
    )  # Interfaz hacia la red pública
    s1.cmd(
        "ifconfig s1-eth2 hw ether 00:00:00:bb:bb:bb"
    )  # Interfaz hacia la red privada

    info("*** Desplegando la CLI de Mininet ***\n")
    CLI(net)

    info("*** Deteniendo la Red ***\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    my_network()
