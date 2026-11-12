import unittest
from pathlib import Path
from backend.simulation.ns2_parser import NS2TraceAnalyzer
from backend.database.db import init_db

class TestNS2Parser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_trace_generation_and_analysis(self):
        sample_file = Path("simulation") / "sample_traces" / "test_unit_trace.tr"
        # Generate flooding trace
        NS2TraceAnalyzer.generate_sample_trace(sample_file, scenario="flooding")
        self.assertTrue(sample_file.exists())

        # Analyze trace
        analysis = NS2TraceAnalyzer.analyze_trace_file(sample_file, scenario_name="Unit Test Flooding")
        self.assertGreater(analysis["total_packets"], 50)
        self.assertGreater(analysis["throughput_kbps"], 0.0)
        self.assertGreater(analysis["packet_loss_ratio"], 0.0)
        self.assertIn("chart_data", analysis)

if __name__ == "__main__":
    unittest.main()
