from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, IPv6, conf
import datetime

def process_packet(packet):
    """
    Callback function to parse and display packet details.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 80)
    print(f" Packet Captured at {timestamp}")
    print("-" * 80)

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"[ETHERNET] {eth.src} -> {eth.dst} | Type: {hex(eth.type)}")

    # IPv4 Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"[IPv4]     {ip.src} -> {ip.dst} | Protocol: {ip.proto} | TTL: {ip.ttl}")
    
    # IPv6 Layer
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        print(f"[IPv6]     {ipv6.src} -> {ipv6.dst} | Next Header: {ipv6.nh}")

    # Transport Layers
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"[TCP]      Port: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags} | Seq: {tcp.seq}")
    
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"[UDP]      Port: {udp.sport} -> {udp.dport} | Length: {udp.len}")

    # ICMP (Ping)
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print(f"[ICMP]     Type: {icmp.type} | Code: {icmp.code}")

    # ARP
    if packet.haslayer(ARP):
        arp = packet[ARP]
        print(f"[ARP]      {arp.psrc} is asking about {arp.pdst} | Op: {arp.op}")

    # Raw Payload Data
    if packet.haslayer("Raw"):
        payload = packet["Raw"].load
        print(f"[DATA]     {payload[:50]}{'...' if len(payload) > 50 else ''}")

    print("=" * 80)

def main():
    print("Starting Network Sniffer...")
    print("Checking for Npcap/WinPcap...")
    
    try:
       
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping Sniffer...")
    except PermissionError:
        print("\nError: Insufficient privileges. Run the terminal as Administrator.")
    except Exception as e:
        if "winpcap is not installed" in str(e).lower():
            print("\n[!] ERROR: Npcap/WinPcap driver is missing.")
            print("Please download and install Npcap from: https://npcap.com/")
            print("Make sure to check 'Install Npcap in WinPcap API-compatible Mode' during setup.")
        else:
            print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()