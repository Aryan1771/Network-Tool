"""Create deterministic PCAP and NS-2 files for manual website testing."""

from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, PcapNgWriter, wrpcap


FIXTURE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = FIXTURE_DIR / "uploads"
NS2_DIR = FIXTURE_DIR / "ns2"
BASE_TIME = 1_767_225_600.0  # 2026-01-01 00:00:00 UTC
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"


def tcp_packet(src, dst, sport, dport, flags, offset, payload=b""):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, seq=1000 + int(offset * 1000)
    )
    if payload:
        packet = packet / Raw(load=payload)
    packet.time = BASE_TIME + offset
    return packet


def make_normal_capture():
    packets = []
    for flow in range(8):
        target = f"198.51.100.{10 + flow}"
        sport = 40000 + flow
        offset = flow * 0.2
        packets.extend((
            tcp_packet("192.0.2.10", target, sport, 443, "S", offset),
            tcp_packet(target, "192.0.2.10", 443, sport, "SA", offset + 0.03),
            tcp_packet("192.0.2.10", target, sport, 443, "A", offset + 0.06),
        ))
    for i in range(4):
        packet = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.0.2.10", dst="198.51.100.53")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"host-{i}.example.test"))
        )
        packet.time = BASE_TIME + 2 + i * 0.2
        packets.append(packet)
    return packets


def make_port_scan():
    return [
        tcp_packet("192.0.2.20", "198.51.100.80", 41000 + i, 1000 + i, "S", i * 0.04)
        for i in range(25)
    ]


def make_brute_force():
    return [
        tcp_packet("192.0.2.30", "198.51.100.22", 42000 + i, 22, "S", i * 0.4)
        for i in range(12)
    ]


def make_syn_flood():
    # Port 65000 avoids also matching the monitored service-port rule.
    return [
        tcp_packet("192.0.2.40", "198.51.100.90", 43000 + (i % 2000), 65000, "S", i * 0.01)
        for i in range(120)
    ]


def make_data_exfiltration():
    packets = []
    for i in range(200):
        packet = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.0.2.50", dst="198.51.100.100")
            / UDP(sport=44000, dport=9000)
            / Raw(load=bytes([i % 256]) * 1400)
        )
        packet.time = BASE_TIME + i * 0.02
        packets.append(packet)
    return packets


def make_mixed_capture():
    scan = make_port_scan()
    ssh = make_brute_force()
    # Keep scenario windows separate and source/target pairs distinct.
    for packet in scan:
        packet.time = BASE_TIME + 10 + (packet.time - BASE_TIME)
        packet[IP].src = "192.0.2.60"
        packet[IP].dst = "198.51.100.110"
        packet[TCP].dport += 1000
        del packet[IP].chksum
        del packet[TCP].chksum
    for packet in ssh:
        packet.time = BASE_TIME + 20 + (packet.time - BASE_TIME)
        packet[IP].src = "192.0.2.61"
        packet[IP].dst = "198.51.100.111"
        del packet[IP].chksum
        del packet[TCP].chksum
    return scan + ssh


def write_trace(path, dropped_every=0, packet_count=40):
    lines = []
    time_value = 0.1
    for packet_id in range(1, packet_count + 1):
        time_value += 0.05
        size = 1000
        lines.append(f"+ {time_value:.4f} 0 1 cbr {size} ------- 1 0.0 3.0 0 {packet_id}")
        if dropped_every and packet_id % dropped_every == 0:
            lines.append(f"d {time_value + 0.01:.4f} 1 2 cbr {size} ------- 1 0.0 3.0 0 {packet_id}")
        else:
            lines.append(f"- {time_value + 0.01:.4f} 0 1 cbr {size} ------- 1 0.0 3.0 0 {packet_id}")
            lines.append(f"r {time_value + 0.04:.4f} 2 3 cbr {size} ------- 1 0.0 3.0 0 {packet_id}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    NS2_DIR.mkdir(parents=True, exist_ok=True)

    captures = {
        "normal_traffic.pcap": make_normal_capture(),
        "port_scan.pcap": make_port_scan(),
        "brute_force.pcap": make_brute_force(),
        "syn_flood.pcap": make_syn_flood(),
        "data_exfiltration.pcap": make_data_exfiltration(),
    }
    for filename, packets in captures.items():
        wrpcap(str(UPLOAD_DIR / filename), packets)

    writer = PcapNgWriter(str(UPLOAD_DIR / "mixed_activity.pcapng"))
    for packet in make_mixed_capture():
        writer.write(packet)
    writer.close()

    write_trace(NS2_DIR / "normal_trace.tr")
    write_trace(NS2_DIR / "packet_loss_trace.tr", dropped_every=4)
    write_trace(NS2_DIR / "flooding_trace.tr", dropped_every=3, packet_count=120)

    print(f"Created {len(captures) + 1} packet captures and 3 NS-2 traces in {FIXTURE_DIR}")


if __name__ == "__main__":
    main()
