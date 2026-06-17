import pyshark

def capture_packets():
    capture = pyshark.LiveCapture(interface="Wi-Fi")

    for packet in capture.sniff_continuously(packet_count=100):
        if hasattr(packet, "ip"):
            if hasattr(packet, "tcp"):
                print(packet.ip.src, "->", packet.ip.dst, packet.transport_layer, "PORT:", packet.tcp.dstport)
            else:
                print(packet.ip.src, "->", packet.ip.dst, packet.transport_layer)
        yield packet
