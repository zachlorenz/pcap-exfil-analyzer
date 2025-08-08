import pyshark
import sys
from analyzer import dns_exfil

def analyze_pcap(file_path):
    print(f"[+] Loading PCAP: {file_path}\n")
    try:
        capture = pyshark.FileCapture(file_path)
    except FileNotFoundError:
        print("[-] Error: File not found.")
        sys.exit(1)

    packet_count = 0
    for packet in capture:
        packet_count += 1
        try:
            src = packet.ip.src
            dst = packet.ip.dst
            protocol = packet.highest_layer
            print(f"Packet #{packet_count}: {src} -> {dst} | Protocol: {protocol}")
        except AttributeError:
            print(f"Packet #{packet_count}: Non-IP packet or malformed")

    print(f"\n[+] Done. Total packets: {packet_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_analyzer.py <path_to_pcap> [--dns]")
        sys.exit(1)

    pcap_file = sys.argv[1]

    if len(sys.argv) > 2 and sys.argv[2] == "--dns":
        dns_exfil.analyze_dns(pcap_file)
    else:
        analyze_pcap(pcap_file)

