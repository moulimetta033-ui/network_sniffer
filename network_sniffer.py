"""
network_sniffer.py
==================
A professional CLI-based network packet sniffer built with Scapy.

Features:
  - Multi-layer packet parsing: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP
  - BPF filter support for targeted capture
  - Interface selection
  - Packet counter with live summary on exit
  - Optional file logging
  - Clean UTF-8 payload decoding with fallback to hex

Author : <Your Name>
Version: 2.0.0
License: MIT
"""

import argparse
import datetime
import signal
import sys
import io

# ---------------------------------------------------------------------------
# FIX: Force UTF-8 output on Windows to avoid encoding errors
# ---------------------------------------------------------------------------
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ---------------------------------------------------------------------------
# Dependency check — give a helpful message if Scapy is missing
# ---------------------------------------------------------------------------
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, IPv6, conf
except ImportError:
    print("[!] Scapy is not installed.  Run:  pip install scapy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
_packet_counter: int = 0
_log_file = None          # Optional open file handle for logging


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_payload(raw: bytes, max_bytes: int = 80) -> str:
    """
    Try to decode raw bytes as UTF-8.
    Fall back to a hex representation if decoding fails.
    """
    sample = raw[:max_bytes]
    suffix = "..." if len(raw) > max_bytes else ""
    try:
        return sample.decode("utf-8", errors="strict") + suffix
    except UnicodeDecodeError:
        return sample.hex(" ") + suffix


def _log(line: str) -> None:
    """Write *line* to stdout and, optionally, to the log file."""
    print(line)
    if _log_file:
        _log_file.write(line + "\n")


# ---------------------------------------------------------------------------
# Core packet handler
# ---------------------------------------------------------------------------

def process_packet(packet) -> None:
    """
    Callback invoked by Scapy for every captured packet.
    """
    global _packet_counter
    _packet_counter += 1

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    _log("\n" + "=" * 80)
    _log(f"  Packet #{_packet_counter:>6}   |   {timestamp}")
    _log("-" * 80)

    # Ethernet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        _log(f"  [ETHERNET]  {eth.src}  ->  {eth.dst}  |  EtherType: {hex(eth.type)}")

    # IPv4
    if packet.haslayer(IP):
        ip = packet[IP]
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, str(ip.proto))
        _log(
            f"  [IPv4]      {ip.src}  ->  {ip.dst}"
            f"  |  Proto: {proto_name}  |  TTL: {ip.ttl}"
            f"  |  Len: {ip.len}"
        )

    # IPv6
    if packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        _log(
            f"  [IPv6]      {ipv6.src}  ->  {ipv6.dst}"
            f"  |  Next-Header: {ipv6.nh}  |  HopLimit: {ipv6.hlim}"
        )

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        _log(
            f"  [TCP]       :{tcp.sport}  ->  :{tcp.dport}"
            f"  |  Flags: {tcp.flags}  |  Seq: {tcp.seq}  |  Ack: {tcp.ack}"
        )
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        _log(
            f"  [UDP]       :{udp.sport}  ->  :{udp.dport}"
            f"  |  Length: {udp.len}"
        )

    # ICMP
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        type_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                      11: "Time Exceeded"}
        type_str = type_names.get(icmp.type, f"Type {icmp.type}")
        _log(f"  [ICMP]      {type_str}  |  Code: {icmp.code}")

    # ARP
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op_str = "REQUEST" if arp.op == 1 else "REPLY"
        _log(
            f"  [ARP]       {op_str}  --  {arp.psrc} ({arp.hwsrc})"
            f"  ->  {arp.pdst} ({arp.hwdst})"
        )

    # Raw payload
    if packet.haslayer("Raw"):
        payload = packet["Raw"].load
        _log(f"  [PAYLOAD]   {_decode_payload(payload)}")

    _log("=" * 80)


# ---------------------------------------------------------------------------
# Signal handler
# ---------------------------------------------------------------------------

def _handle_sigint(sig, frame) -> None:
    _print_summary()
    sys.exit(0)


def _print_summary() -> None:
    _log(f"\n{'=' * 80}")
    _log(f"  Capture stopped.  Total packets captured: {_packet_counter}")
    _log(f"{'=' * 80}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global _log_file

    parser = argparse.ArgumentParser(
        prog="network_sniffer",
        description="Professional network packet sniffer powered by Scapy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Sniff everything on the default interface
  python network_sniffer.py

  # Sniff only HTTP traffic on eth0
  python network_sniffer.py -i eth0 -f "tcp port 80"

  # Capture 50 DNS packets and save to a log file
  python network_sniffer.py -f "udp port 53" -c 50 -o dns_capture.log
        """,
    )
    parser.add_argument("-i", "--iface",  default=None,
                        help="Interface to sniff on (default: system default)")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF filter string (e.g. 'tcp port 443')")
    parser.add_argument("-c", "--count",  type=int, default=0,
                        help="Max packets to capture; 0 = infinite (default: 0)")
    parser.add_argument("-o", "--output", default=None,
                        help="Log file path (appends if file exists)")

    args = parser.parse_args()

    # Optional log file
    if args.output:
        try:
            _log_file = open(args.output, "a", encoding="utf-8")
        except OSError as e:
            print(f"[!] Cannot open log file '{args.output}': {e}")
            sys.exit(1)

    # Banner (using plain ASCII characters instead of Unicode box chars)
    print("+" + "=" * 78 + "+")
    print("|" + "  NETWORK SNIFFER  v2.0.0".center(78) + "|")
    print("+" + "=" * 78 + "+")
    print(f"  Interface : {args.iface or 'default'}")
    print(f"  BPF Filter: {args.filter or 'none'}")
    print(f"  Pkt Limit : {args.count if args.count > 0 else 'unlimited'}")
    print(f"  Log File  : {args.output or 'none'}")
    print("  Press Ctrl+C to stop.\n")

    # Register signal handler
    signal.signal(signal.SIGINT, _handle_sigint)

    # Start capture
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            count=args.count,
            prn=process_packet,
            store=False,
        )
        _print_summary()

    except PermissionError:
        print("\n[!] Insufficient privileges.  Run as Administrator.")
        sys.exit(1)
    except Exception as exc:
        msg = str(exc).lower()
        if "winpcap" in msg or "npcap" in msg:
            print("\n[!] Npcap/WinPcap driver not found.")
            print("    Download from: https://npcap.com/")
            print("    Enable 'WinPcap API-compatible Mode' during installation.")
        else:
            print(f"\n[!] Unexpected error: {exc}")
        sys.exit(1)
    finally:
        if _log_file:
            _log_file.close()


if __name__ == "__main__":
    main()
