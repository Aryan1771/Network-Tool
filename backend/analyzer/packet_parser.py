from datetime import datetime
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
except ImportError:
    pass

class PacketParser:
    """
    Forensic Packet Parser:
    Extracts strictly header metadata for digital forensic analysis.
    Adheres to forensic privacy standard: never extracts, stores, or exposes application payloads.
    """

    @staticmethod
    def parse_scapy_packet(pkt, session_id=None, is_demo=0):
        """
        Parses a Scapy packet into normalized dictionary metadata.
        """
        timestamp = float(getattr(pkt, "time", datetime.now().timestamp()))
        dt_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        packet_size = len(pkt)
        
        src_mac = None
        dst_mac = None
        if pkt.haslayer("Ether"):
            ether = pkt["Ether"]
            src_mac = ether.src
            dst_mac = ether.dst

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags = None
        info_parts = []

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto_num = ip.proto
            
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                protocol = "TCP"
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                
                # Decode TCP Flags
                flags = []
                f = tcp.flags
                # Scapy flags can be checked with bitwise or string representations
                if 'F' in f: flags.append("FIN")
                if 'S' in f: flags.append("SYN")
                if 'R' in f: flags.append("RST")
                if 'P' in f: flags.append("PSH")
                if 'A' in f: flags.append("ACK")
                if 'U' in f: flags.append("URG")
                tcp_flags = ", ".join(flags) if flags else "NONE"
                info_parts.append(f"TCP {src_port} -> {dst_port} [{tcp_flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}")
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                protocol = "UDP"
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                
                if pkt.haslayer(DNS):
                    protocol = "DNS"
                    info_parts.append(f"DNS Query/Response ({src_port} -> {dst_port})")
                else:
                    info_parts.append(f"UDP {src_port} -> {dst_port} Len={udp.len}")
            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                protocol = "ICMP"
                icmp_types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
                type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
                info_parts.append(f"ICMP {type_name} (code={icmp.code})")
            else:
                protocol = f"IP({proto_num})"
                info_parts.append(f"IP Proto={proto_num} Len={ip.len}")
        elif pkt.haslayer(ARP):
            protocol = "ARP"
            arp = pkt[ARP]
            src_ip = arp.psrc
            dst_ip = arp.pdst
            src_mac = arp.hwsrc
            dst_mac = arp.hwdst
            op = "Who has" if arp.op == 1 else "Is-at" if arp.op == 2 else f"Op={arp.op}"
            info_parts.append(f"ARP {op} {dst_ip} Tell {src_ip}")
        else:
            protocol = pkt.summary().split()[0] if pkt.summary() else "RAW"
            info_parts.append(pkt.summary() or "Non-IP Packet")

        info_str = " | ".join(info_parts) if info_parts else f"{protocol} {src_ip} -> {dst_ip}"

        return {
            "session_id": session_id or "default-session",
            "timestamp": timestamp,
            "datetime_str": dt_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": packet_size,
            "tcp_flags": tcp_flags,
            "src_mac": src_mac or "N/A",
            "dst_mac": dst_mac or "N/A",
            "info": info_str,
            "is_suspicious": 0,
            "is_demo": is_demo
        }
