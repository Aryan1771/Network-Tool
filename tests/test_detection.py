import unittest
import time
from backend.database.db import init_db
from backend.detector.rules import DetectionRules

class TestDetectionRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_port_scan_rule(self):
        # 25 unique destination ports in 2 seconds
        now = time.time()
        packets = []
        for p in range(25):
            packets.append({
                "timestamp": now + (p * 0.08),
                "datetime_str": "2026-11-11 12:00:00",
                "src_ip": "10.0.0.99",
                "dst_ip": "192.168.1.1",
                "src_port": 50000 + p,
                "dst_port": 1000 + p,
                "protocol": "TCP",
                "tcp_flags": "SYN"
            })
        incidents = DetectionRules.evaluate_port_scan(packets)
        self.assertGreaterEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "PORT_SCAN")
        self.assertEqual(incidents[0]["severity"], "MEDIUM")

    def test_syn_flood_rule(self):
        # 110 SYN packets within 0.8s
        now = time.time()
        packets = []
        for i in range(110):
            packets.append({
                "timestamp": now + (i * 0.007),
                "datetime_str": "2026-11-11 12:00:00",
                "src_ip": "172.16.0.45",
                "dst_ip": "192.168.1.100",
                "src_port": 40000 + (i % 1000),
                "dst_port": 80,
                "protocol": "TCP",
                "tcp_flags": "SYN"
            })
        incidents = DetectionRules.evaluate_syn_flood(packets)
        self.assertGreaterEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "SYN_FLOOD")
        self.assertEqual(incidents[0]["severity"], "HIGH")

    def test_brute_force_rule(self):
        # 14 attempts to port 22 in 15 seconds
        now = time.time()
        packets = []
        for i in range(14):
            packets.append({
                "timestamp": now + (i * 1.0),
                "datetime_str": "2026-11-11 12:00:00",
                "src_ip": "198.51.100.23",
                "dst_ip": "192.168.1.50",
                "src_port": 45000 + i,
                "dst_port": 22,
                "protocol": "TCP",
                "tcp_flags": "SYN"
            })
        incidents = DetectionRules.evaluate_brute_force(packets)
        self.assertGreaterEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "BRUTE_FORCE")

    def test_data_exfiltration_rule(self):
        # 280,000 bytes outbound
        now = time.time()
        packets = []
        for i in range(200):
            packets.append({
                "timestamp": now + (i * 0.1),
                "datetime_str": "2026-11-11 12:00:00",
                "src_ip": "192.168.1.150",
                "dst_ip": "203.0.113.88",
                "src_port": 52341,
                "dst_port": 443,
                "protocol": "TCP",
                "packet_size": 1400
            })
        incidents = DetectionRules.evaluate_data_exfiltration(packets)
        self.assertGreaterEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "DATA_EXFILTRATION")

if __name__ == "__main__":
    unittest.main()
