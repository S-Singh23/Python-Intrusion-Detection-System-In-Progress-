import time
from collections import defaultdict

ALERT_COOLDOWN = 10

last_alert_time = defaultdict(float)
summary_count = defaultdict(int)


def extract_packet_info(packet):
    try:
        src = packet.ip.src if hasattr(packet, "ip") else "N/A"
        dst = packet.ip.dst if hasattr(packet, "ip") else "N/A"
        proto = packet.transport_layer if hasattr(packet, "transport_layer") else "N/A"

        port = "-"
        if hasattr(packet, "tcp"):
            port = packet.tcp.dstport

        return f"{src} -> {dst} | {proto} | PORT: {port}"
    except:
        return "Packet info unavailable"


def log_alert(alert_type, source, packet=None, detail=""):
    now = time.time()
    key = f"{alert_type}:{source}"

    # cooldown to stop spam
    if now - last_alert_time[key] < ALERT_COOLDOWN:
        return

    last_alert_time[key] = now
    summary_count[key] += 1

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

    packet_info = extract_packet_info(packet) if packet else ""

    message = f"[{timestamp}] {alert_type} | Source: {source}"
    if detail:
        message += f" | {detail}"
    if packet_info:
        message += f" | {packet_info}"

    print(message)

    # detailed log file (with packet info)
    with open("alert_log.txt", "a") as f:
        f.write(message + "\n")

    # optional: store FULL packet dump (heavy but useful)
    if packet:
        try:
            with open("packet_dump.txt", "a") as f:
                f.write("\n" + "="*50 + "\n")
                f.write(f"{timestamp} - {alert_type}\n")
                f.write(str(packet) + "\n")
        except:
            pass

    write_summary()


def write_summary():
    with open("alert_summary.txt", "w") as f:
        f.write("ALERT SUMMARY\n")
        f.write("====================\n")
        for key, count in summary_count.items():
            f.write(f"{key} -> {count}\n")
