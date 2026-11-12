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

    def test_configured_password_protects_pages_but_not_health(self):
        original_password = app.config.get("APP_PASSWORD", "")
        original_username = app.config.get("APP_USERNAME", "analyst")
        app.config["APP_PASSWORD"] = "test-password"
        app.config["APP_USERNAME"] = "test-user"
        try:
            with self.client.get("/") as response:
                self.assertEqual(response.status_code, 401)
                self.assertIn("WWW-Authenticate", response.headers)
            with self.client.get("/", auth=("test-user", "test-password")) as response:
                self.assertEqual(response.status_code, 200)
            with self.client.post(
                "/api/settings", json={}, auth=("test-user", "test-password"),
                headers={"Origin": "https://attacker.example"}
            ) as response:
                self.assertEqual(response.status_code, 403)
            with self.client.get("/health") as response:
                self.assertEqual(response.status_code, 200)
        finally:
            app.config["APP_PASSWORD"] = original_password
            app.config["APP_USERNAME"] = original_username


if __name__ == "__main__":
    unittest.main()
