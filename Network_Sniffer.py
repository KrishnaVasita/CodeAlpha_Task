from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import binascii

non_ip_count = 0  # Counter for non-IP packets

def format_payload(raw_data):
    if not raw_data:
        return "No payload"
    hex_data = binascii.hexlify(raw_data).decode()
    ascii_data = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_data])
    return f"\nHex   : {hex_data[:64]}...\nASCII : {ascii_data[:64]}..."

def process_packet(pkt):
    global non_ip_count
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto

        # Identify protocol
        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, "Other")

        print("\n\033[1;36m--- IP Packet Captured ---\033[0m")
        print(f"Time           : {timestamp}")
        print(f"Protocol       : {proto_num} ({protocol_name})")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # Show ports for TCP/UDP
        if TCP in pkt:
            print(f"Source Port    : {pkt[TCP].sport}")
            print(f"Destination Port: {pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"Source Port    : {pkt[UDP].sport}")
            print(f"Destination Port: {pkt[UDP].dport}")

        # Payload
        if Raw in pkt:
            payload_data = pkt[Raw].load
            print("Payload        :", format_payload(payload_data))
        else:
            print("Payload        : No payload")

        # Log to file
        with open("packets_log.txt", "a") as log:
            log.write(f"{timestamp} | {protocol_name} | {src_ip} -> {dst_ip}\n")

    else:
        non_ip_count += 1

def start_sniffing(interface="Wi-Fi", packet_count=10):
    print(f"\n[INFO] Starting packet capture on interface: {interface}")
    print(f"[INFO] Capturing {packet_count} packets... Press Ctrl+C to stop manually.\n")
    
    try:
        sniff(count=packet_count, prn=process_packet, iface=interface)
    except Exception as e:
        print(f"[ERROR] {e}")

    print(f"\n[INFO] Packet capture complete.")
    if non_ip_count:
        print(f"[INFO] {non_ip_count} non-IP packets were ignored.")

# Entry point
if __name__ == "__main__":
    start_sniffing(interface="Wi-Fi", packet_count=10)
