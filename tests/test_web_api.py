"""Read-only API smoke tests for the website dashboard."""

import unittest

from app import app
from backend.database.db import close_db


class WebsiteApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        close_db()

    def test_dashboard_apis_return_json(self):
        endpoints = (
            "/api/stats/overview",
            "/api/stats/activity-timeline",
            "/api/stats/protocol-distribution",
            "/api/stats/incident-distribution",
            "/api/capture/interfaces",
            "/api/capture/status",
            "/api/packets",
            "/api/incidents",
            "/api/chain-of-custody",
        )
        for path in endpoints:
            with self.subTest(path=path):
                with self.client.get(path) as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertTrue(response.is_json)
                    self.assertIsNotNone(response.get_json())

    def test_packet_api_keeps_expected_envelope(self):
        with self.client.get("/api/packets") as response:
            payload = response.get_json()
            self.assertIn("packets", payload)
            self.assertIn("total", payload)
            self.assertIsInstance(payload["packets"], list)


if __name__ == "__main__":
    unittest.main()
