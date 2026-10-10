"""Integration tests for Local Laya AI API Endpoints.

Tests:
- /health and /api/health endpoints
- /api/classify with valid, empty, and malformed inputs
- /api/quantify with complete telemetry payload
- Output schema verification against frontend expectations
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from backend.service import app

client = TestClient(app)


class TestLayaApiEndpoints(unittest.TestCase):

    def test_health_check(self):
        """Verify health check endpoint returns 200 and expected engine metadata."""
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("engine", data)
        self.assertIn("model", data)
        self.assertEqual(data["engine"], "Local Laya AI")
        self.assertEqual(data["model"], "convaiinnovations/laya")
        self.assertTrue(data["ready"])

    def test_classify_valid_input(self):
        """Verify classification of a valid cyber risk finding."""
        payload = {
            "state": "LockBit 3.0 ransomware executable encrypting production MySQL database volumes",
            "targetGroup": "Database Hosts",
            "source": "EDR + SIEM"
        }
        response = client.post("/api/classify", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("domain", data)
        self.assertIn(data["domain"], ["internal", "external", "machines"])
        self.assertIn("severity", data)
        self.assertIn(data["severity"], ["Severe", "Medium", "Ignorable"])
        self.assertIn("recommendation", data)
        self.assertIn("activeExploitLikelihood", data)
        self.assertIsInstance(data["activeExploitLikelihood"], float)
        self.assertIn("inferenceTimeMs", data)

    def test_classify_empty_input(self):
        """Verify that empty inputs are rejected with 400 or 422."""
        response = client.post("/api/classify", json={"state": "  "})
        self.assertIn(response.status_code, [400, 422])

    def test_classify_malformed_input(self):
        """Verify that missing required fields are rejected with 422."""
        response = client.post("/api/classify", json={"invalid_field": 123})
        self.assertEqual(response.status_code, 422)

    def test_quantify_endpoint_schema(self):
        """Verify that /api/quantify returns the exact structured schema expected by the frontend."""
        payload = {
            "filename": "test_bundle.zip",
            "fileCount": 3,
            "fileDetails": [
                {"name": "siem_telemetry_events.json", "size": 2048, "sourceType": "SIEM Telemetry"},
                {"name": "edr_endpoint_telemetry.csv", "size": 1024, "sourceType": "EDR Telemetry"},
                {"name": "iam_identity_matrix.json", "size": 4096, "sourceType": "IAM Telemetry"}
            ],
            "detectedSources": {
                "siem": True,
                "edr": True,
                "iam": True
            }
        }
        response = client.post("/api/quantify", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 18)

        # Check expected schema fields on every returned finding
        required_fields = [
            "id", "category", "name", "targetGroup", "source", "threatActor",
            "attackVector", "cveList", "complianceImpact", "annualProbability",
            "lossIfIgnored", "solutionCost", "lossBreakdown", "severity",
            "technicalFinding", "businessImpact", "solutionPlan", "recommendation",
            "aiEngine"
        ]

        for item in data:
            for field in required_fields:
                self.assertIn(field, item, f"Missing required field '{field}' in item {item.get('id')}")

            # Verify categorical bounds
            self.assertIn(item["category"], ["internal", "external", "machines"])
            self.assertIn(item["severity"], ["Severe", "Medium", "Ignorable"])
            self.assertIsInstance(item["lossIfIgnored"], (int, float))
            self.assertIsInstance(item["solutionCost"], (int, float))
            self.assertGreater(item["lossIfIgnored"], 0)
            self.assertGreater(item["solutionCost"], 0)


if __name__ == "__main__":
    unittest.main()
