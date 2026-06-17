from packet_capture import capture_packets
from detector import detect_packet

for packet in capture_packets():
    detect_packet(packet)
