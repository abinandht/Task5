from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        
        if protocol == 6:  # TCP
            print("Protocol: TCP")
            if TCP in packet:
                print(f"Payload: {packet[TCP].payload}")
        elif protocol == 17:  # UDP
            print("Protocol: UDP")
            if UDP in packet:
                print(f"Payload: {packet[UDP].payload}")
        else:
            print("Protocol: Other")
        
        print("-" * 40)

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
  
