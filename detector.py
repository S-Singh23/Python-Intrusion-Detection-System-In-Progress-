import time
from collections import defaultdict
from collections import deque
from alerts import log_alert

packet_count = defaultdict(deque)
global_packets = deque()
icmp_count = defaultdict(deque)

def flood_detection(packet):
    now = time.time()

    try:
        # For a DoS Attack: -----------------------------------------------------------------
        src = packet.ip.src
        if(packet.transport_layer != "ICMP"):
            packet_count[src].append(now)
        
        while packet_count[src] and packet_count[src][0] < now - 5:
            packet_count[src].popleft()

        current_count = len(packet_count[src])
        if current_count > 100:
            log_alert("Packet Flood", src, packet, f"Packets: {current_count}")

        # For a DDoS attack: ---------------------------------------------------------------
        global_packets.append(now)

        while global_packets and global_packets[0] < now - 5:
            global_packets.popleft()

        if len(global_packets) > 1000:
            log_alert("DDoS Spike", "GLOBAL", packet, f"Packets: {len(global_packets)}")

        # ICMP Attack: ---------------------------------------------------------------------
        
        if packet.transport_layer == "ICMP":
            icmp_count[src].append(now)
            while icmp_count[src] and icmp_count[src][0] < now - 5:
                icmp_count[src].popleft()

            current_count_ICMP = len(icmp_count[src])
            if current_count_ICMP > 100:
                log_alert("ICMP Flood", src, packet, f"Packets: {current_count_ICMP}")

    except AttributeError:
        pass

        

port_count = defaultdict(lambda: defaultdict(deque))

SUSPICIOUS_PORTS = {22, 23, 21, 3389, 4444, 5555, 6667, 12345}
BRUTEFORCE_PORTS = {22, 3389, 21, 23}
def port_scan(packet):
    now = time.time()
    
    try:
        if packet.transport_layer == "TCP":
            port = packet.tcp.dstport
            ip = packet.ip.src
            port_count[ip][port].append(now)

        # Port Scan Attack ----------------------------------------------------------------------
            for p in list(port_count[ip]):
                    while port_count[ip][p] and port_count[ip][p][0] < now - 5:
                        port_count[ip][p].popleft()

                    if not port_count[ip][p]:
                        del port_count[ip][p]

            current_count = len(port_count[ip])
            susPorts_list = []
            if (current_count > 10):
                for p in port_count[ip]:
                    try:
                        port_num = int(p)

                        if port_num in SUSPICIOUS_PORTS:
                            susPorts_list.append(port_num)
                    except ValueError:
                        continue
                susPorts_list = sorted(set(susPorts_list))
                if(susPorts_list):
                    log_alert("Suspicious Port Access", ip, packet, f"Ports: {susPorts_list}")
                
                log_alert("Port Scan", ip, packet, f"Ports: {current_count}")

        # Brute Force Attack: ------------------------------------------------------------------
            
            try:
                port_num = int(port)

                if len(port_count[ip][port]) > 10 and port_num in BRUTEFORCE_PORTS:
                    log_alert("Brute Force Attack", ip, packet, f"Port: {port_num}")

                elif len(port_count[ip][port]) > 50:
                    log_alert("Possible Brute Force Attack", ip, packet, f"Port: {port_num}")

            except ValueError:
                pass    

    except AttributeError:
        pass

syn_count = defaultdict(deque)

def syn_flood(packet):
    now = time.time()

    try:
        if(packet.transport_layer == "TCP"):
            syn_flag = str(packet.tcp.flags_syn)
            ack_flag = str(packet.tcp.flags_ack)

            if syn_flag in ["1", "True"] and ack_flag in ["0", "False"]:
                src = packet.ip.src
                syn_count[src].append(now)

                while syn_count[src] and syn_count[src][0] < now - 5:
                    syn_count[src].popleft()

                current_count = len(syn_count[src])
                if current_count > 100:
                    log_alert("SYN Flood", src, packet, f"SYN count: {current_count}")

    except AttributeError:
        pass

arp_table = defaultdict(set)

def arp_spoofing(packet):
    try:
        if hasattr(packet, "arp"):
            ip = packet.arp.src_proto_ipv4
            mac = packet.arp.src_hw_mac

            if mac not in arp_table[ip]:
                arp_table[ip].add(mac)

                if len(arp_table[ip]) > 1:
                    log_alert("ARP Spoofing", ip, packet, f"MACs: {sorted(arp_table[ip])}")

    except AttributeError:
        pass

def detect_packet(packet):

    flood_detection(packet)
    port_scan(packet)
    syn_flood(packet)
    arp_spoofing(packet)
