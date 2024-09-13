from curses import raw
from multiprocessing import RawValue
from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Determine the protocol and print relevant information
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Src Port: {tcp_layer.sport} | Dst Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Src Port: {udp_layer.sport} | Dst Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("Protocol: ICMP")

        # Print the raw payload data (if any)
        if packet.haslayer(raw):
            payload = packet[RawValue].load
            print(f"Payload: {payload}\n")
        else:
            print("No payload available.\n")

def main():
    print("Starting packet sniffer...")
    # Start sniffing; capture the first 10 packets (adjust as needed)
    sniff(prn=process_packet, count=10)

if __name__ == "__main__":
    main()
