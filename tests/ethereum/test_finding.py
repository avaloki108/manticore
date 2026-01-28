"""
Unit tests for Finding data structure and FindingSink.
"""
import json
import os
import tempfile
import unittest
from manticore.ethereum.finding import Finding, FindingSink


class TestFinding(unittest.TestCase):
    """Test cases for Finding dataclass and serialization."""

    def test_finding_creation(self):
        """Test that a Finding can be created with all required fields."""
        finding = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
            sender=0xabcdef1234567890abcdef1234567890abcdef12,
            data="0xa9059cbb000000000000000000000000000000000000000000000000000000",
            value=1000000000000000000,
            pc=100,
            tx_index=0,
            chain_id=1,
            workspace_path="/tmp/workspace",
            tags=["authorization", "access-control"],
        )
        self.assertEqual(finding.kind, "AUTHORIZATION_BYPASS")
        self.assertEqual(finding.description, "Unauthorized access detected")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.address, 0x1234567890abcdef1234567890abcdef12345678)
        self.assertEqual(finding.sender, 0xabcdef1234567890abcdef1234567890abcdef12)
        self.assertEqual(finding.data, "0xa9059cbb000000000000000000000000000000000000000000000")
        self.assertEqual(finding.value, 1000000000000000000)
        self.assertEqual(finding.pc, 100)
        self.assertEqual(finding.tx_index, 0)
        self.assertEqual(finding.chain_id, 1)
        self.assertEqual(finding.workspace_path, "/tmp/workspace")
        self.assertEqual(finding.tags, ["authorization", "access-control"])

    def test_finding_to_dict(self):
        """Test that Finding.to_dict() converts int addresses to hex strings."""
        finding = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
            sender=0xabcdef1234567890abcdef1234567890abcdef12,
            data="0xa9059cbb000000000000000000000000000000000000000000000",
            value=1000000000000000000,
            pc=100,
            tx_index=0,
            chain_id=1,
            workspace_path="/tmp/workspace",
            tags=["authorization", "access-control"],
        )
        result = finding.to_dict()
        self.assertEqual(result["kind"], "AUTHORIZATION_BYPASS")
        self.assertEqual(result["description"], "Unauthorized access detected")
        self.assertEqual(result["severity"], "HIGH")
        # Address should be hex string with 0x prefix
        self.assertEqual(result["address"], "0x1234567890abcdef1234567890abcdef12345678")
        self.assertEqual(result["sender"], "0xabcdef1234567890abcdef1234567890abcdef12")
        self.assertEqual(result["data"], "0xa9059cbb000000000000000000000000000000000000000000")
        self.assertEqual(result["value"], 1000000000000000000)
        self.assertEqual(result["pc"], 100)
        self.assertEqual(result["tx_index"], 0)
        self.assertEqual(result["chain_id"], 1)
        self.assertEqual(result["workspace_path"], "/tmp/workspace")
        self.assertEqual(result["tags"], ["authorization", "access-control"])
        # Verify id and timestamp are present
        self.assertIn("id", result)
        self.assertIn("timestamp", result)

    def test_finding_id_stability(self):
        """Test that Finding.id is stable (same input produces same hash)."""
        finding1 = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
            data="0xa9059cbb000000000000000000000000000000000000000000",
            pc=100,
        )
        finding2 = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
            data="0xa9059cbb000000000000000000000000000000000000000000",
            pc=100,
        )
        # Same inputs should produce same ID
        self.assertEqual(finding1.id, finding2.id)

    def test_finding_id_uniqueness(self):
        """Test that different findings produce different IDs."""
        finding1 = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
            data="0xa9059cbb000000000000000000000000000000000000",
            pc=100,
        )
        finding2 = Finding(
            kind="INTEGER_OVERFLOW",
            description="Overflow detected",
            severity="CRITICAL",
            address=0x1234567890abcdef1234567890abcdef12345678,
            data="0xa9059cbb000000000000000000000000000000000000000000",
            pc=200,
        )
        # Different inputs should produce different IDs
        self.assertNotEqual(finding1.id, finding2.id)

    def test_finding_optional_fields(self):
        """Test that optional fields can be omitted."""
        finding = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
        )
        result = finding.to_dict()
        self.assertEqual(result["kind"], "AUTHORIZATION_BYPASS")
        self.assertEqual(result["description"], "Unauthorized access detected")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["address"], "0x1234567890abcdef1234567890abcdef12345678")
        # Optional fields should be None or empty
        self.assertIsNone(result["sender"])
        self.assertEqual(result["data"], "")
        self.assertEqual(result["value"], 0)
        self.assertEqual(result["pc"], 0)
        self.assertIsNone(result["tx_index"])
        self.assertIsNone(result["chain_id"])
        self.assertIsNone(result["workspace_path"])
        self.assertEqual(result["tags"], [])


class TestFindingSink(unittest.TestCase):
    """Test cases for FindingSink collection and JSON output."""

    def test_finding_sink_add_finding(self):
        """Test that findings can be added to FindingSink."""
        sink = FindingSink()
        finding = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
        )
        sink.add_finding(finding)
        self.assertEqual(len(sink.get_findings()), 1)

    def test_finding_sink_get_findings(self):
        """Test that get_findings returns all added findings."""
        sink = FindingSink()
        finding1 = Finding(
            kind="AUTHORIZATION_BYPASS",
            description="Unauthorized access detected",
            severity="HIGH",
            address=0x1234567890abcdef1234567890abcdef12345678,
        )
        finding2 = Finding(
            kind="INTEGER_OVERFLOW",
            description="Overflow detected",
            severity="CRITICAL",
            address=0xabcdef1234567890abcdef1234567890abcdef12,
        )
        sink.add_finding(finding1)
        sink.add_finding(finding2)
        findings = sink.get_findings()
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].kind, "AUTHORIZATION_BYPASS")
        self.assertEqual(findings[1].kind, "INTEGER_OVERFLOW")

    def test_finding_sink_write_json(self):
        """Test that write_json() writes valid JSON to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "findings.json")
            sink = FindingSink(output_path)
            finding1 = Finding(
                kind="AUTHORIZATION_BYPASS",
                description="Unauthorized access detected",
                severity="HIGH",
                address=0x1234567890abcdef1234567890abcdef12345678,
                sender=0xabcdef1234567890abcdef1234567890abcdef12,
                data="0xa9059cbb000000000000000000000000000000000000000",
                value=1000000000000000000,
                pc=100,
                tx_index=0,
                chain_id=1,
                workspace_path="/tmp/workspace",
                tags=["authorization", "access-control"],
            )
            finding2 = Finding(
                kind="INTEGER_OVERFLOW",
                description="Overflow detected",
                severity="CRITICAL",
                address=0xabcdef1234567890abcdef1234567890abcdef12,
            )
            sink.add_finding(finding1)
            sink.add_finding(finding2)
            sink.write_json()

            # Verify file was created
            self.assertTrue(os.path.exists(output_path))

            # Verify JSON is valid
            with open(output_path, "r") as f:
                data = json.load(f)

            # Verify structure
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 2)

            # Verify first finding
            self.assertEqual(data[0]["kind"], "AUTHORIZATION_BYPASS")
            self.assertEqual(data[0]["description"], "Unauthorized access detected")
            self.assertEqual(data[0]["severity"], "HIGH")
            self.assertEqual(data[0]["address"], "0x1234567890abcdef1234567890abcdef12345678")
            self.assertEqual(data[0]["sender"], "0xabcdef1234567890abcdef1234567890abcdef12")
            self.assertEqual(data[0]["data"], "0xa9059cbb000000000000000000000000000000000000")
            self.assertEqual(data[0]["value"], 1000000000000000000)
            self.assertEqual(data[0]["pc"], 100)
            self.assertEqual(data[0]["tx_index"], 0)
            self.assertEqual(data[0]["chain_id"], 1)
            self.assertEqual(data[0]["workspace_path"], "/tmp/workspace")
            self.assertEqual(data[0]["tags"], ["authorization", "access-control"])
            self.assertIn("id", data[0])
            self.assertIn("timestamp", data[0])

            # Verify second finding
            self.assertEqual(data[1]["kind"], "INTEGER_OVERFLOW")
            self.assertEqual(data[1]["description"], "Overflow detected")
            self.assertEqual(data[1]["severity"], "CRITICAL")
            self.assertEqual(data[1]["address"], "0xabcdef1234567890abcdef1234567890abcdef12")


if __name__ == "__main__":
    unittest.main()
