- Iniciar controlador POX:
    python3 pox/pox.py log.level --DEBUG protorouter
- Iniciar topología:
    sudo python3 topologia.py
- abrir hosts (en mininet)
    xterm h1 h2 h3

# pruebas


- setup
python3 pox.py protorouter

sudo python3 topo.py

xterm h1 h2 h3

- un cliente un server
 Que la conexión llegue al server iperf desde la IP pública del NAT.
 La traducción de IP y puerto origen (visibles en las salidas de iperf).
 Los paquetes observados en Wireshark:
 Intercambio de ARP (requests y replies)
 IPs, MACs, puertos TCP/UDP, etc..
 La instalación de flujos en el switch:
 sudo ovs-ofctl dump-flows s1  en otra terminal de Linux.
 Interpretar el significado de los principales campos de los flujos instalados.
 Repetir con UDP.

mininet> h1 wireshark >/dev/null 2>&1 &
mininet> h2 wireshark >/dev/null 2>&1 &

- tcp
en h1   
iperf -s

en h2
iperf -c 200.0.0.1

- udp

en h1
iperf -s

en h2
iperf -c 200.0.0.1 -u -b 1M -l 512

 - Prueba con Múltiples Clientes
 Ejecutar simultáneamente 2 o 3 clientes iperf desde distintos hosts de la red privada.
 Realizar las pruebas tanto con TCP como con UDP.
 Verificar, mediante las salidas de iperf, la traducción de direcciones IP y puertos para cada conexión.
 Explicar cómo la implementación distingue y mantiene el estado de múltiples conexiones concurrentes.

 - tcp
en h1
 iperf -s

en h2
 iperf -c 200.0.0.1 -t 20 &

en h3
 iperf -c 200.0.0.1 -t 20 &

 - udp

 en h1
 iperf -s

 en h2
iperf -c 200.0.0.1 -t 20 &

en h3
iperf -c 200.0.0.1 -t 20 &

Explicación de la implementación
 Durante la demo, cualquiera de los integrantes del grupo podrá ser consultado sobre la implementación. Todos deberán poder explicar:
 La resolución dinámica de ARP.
 La estructura de la tabla NAT/PAT utilizada.
 La asignación de puertos públicos.
 La instalación y expiración de flujos OpenFlow.
 Cómo se maneja el envío de paquetes cuando aún no se conoce la dirección MAC de destino.

en la tercer terminal puedo hacer
sudo ovs-ofctl dump-flows s1

para ver estado de los flujos


- test comunicacion entre privados (tcp)
en h2
iperf -s 

en h3
iperf -c 192.168.1.2