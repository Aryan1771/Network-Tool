"""Smoke tests for the Flask pages and frontend assets."""

import unittest

from app import app
from backend.database.db import close_db


class WebsitePageSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        close_db()

    def test_pages_render_successfully(self):
        pages = (
            "/",
            "/live-traffic",
            "/packet-analyzer",
            "/incident-detection",
            "/timeline",
            "/evidence-vault",
            "/chain-of-custody",
            "/ns2-simulation",
            "/reports",
            "/evaluation",
            "/settings",
        )
        for path in pages:
            with self.subTest(path=path):
                with self.client.get(path) as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("text/html", response.content_type)

    def test_frontend_assets_are_served(self):
        assets = (
            "/static/css/styles.css",
            "/static/js/api.js",
            "/static/js/charts.js",
            "/static/js/main.js",
        )
        for path in assets:
            with self.subTest(path=path):
                with self.client.get(path) as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertGreater(len(response.data), 0)


if __name__ == "__main__":
    unittest.main()
