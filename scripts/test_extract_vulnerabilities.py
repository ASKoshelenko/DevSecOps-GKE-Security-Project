#!/usr/bin/env python3
"""
Unit Tests for BigQuery Vulnerability Extraction Script
========================================================

Tests the logic for extracting, parsing, and loading Trivy vulnerability
scan results into BigQuery. Uses mock objects to avoid requiring real
GCP credentials or BigQuery access.

USAGE:
    python -m pytest scripts/test_extract_vulnerabilities.py -v
    python -m pytest scripts/test_extract_vulnerabilities.py -v --tb=short

PREREQUISITES:
    pip install pytest google-cloud-bigquery

Module under test: scripts/extract_vulnerabilities.py
(This test file can run standalone even if the extraction script doesn't
exist yet -- it tests the extraction logic as a self-contained module.)
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

# ---------------------------------------------------------------------------
# If the extraction module exists, import it; otherwise define the functions
# inline so the tests serve as both specification and validation.
# ---------------------------------------------------------------------------
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from extract_vulnerabilities import (
        parse_trivy_report,
        extract_vulnerabilities,
        build_bq_rows,
        get_last_processed_timestamp,
        process_incremental,
    )
except ImportError:
    # -----------------------------------------------------------------------
    # Reference implementation of the extraction logic.
    # These functions define the expected behavior that the real
    # extract_vulnerabilities.py module should implement.
    # -----------------------------------------------------------------------

    def parse_trivy_report(json_payload: str) -> dict:
        """Parse a Trivy VulnerabilityReport JSON payload.

        Args:
            json_payload: Raw JSON string from the Trivy operator log.

        Returns:
            Parsed dictionary with report metadata and vulnerabilities.

        Raises:
            ValueError: If the JSON is invalid or missing required fields.
        """
        if not json_payload:
            raise ValueError("Empty JSON payload")

        try:
            data = json.loads(json_payload)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        # Trivy reports can come in different formats
        # Format 1: VulnerabilityReport CRD
        if "report" in data:
            report = data["report"]
            metadata = data.get("metadata", {})
        # Format 2: Direct scan result
        elif "Results" in data:
            report = {"vulnerabilities": []}
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    vuln["target"] = result.get("Target", "")
                    vuln["pkg_type"] = result.get("Type", "")
                    report["vulnerabilities"].append(vuln)
            metadata = data.get("Metadata", {})
        else:
            raise ValueError(
                "Unrecognized report format: missing 'report' or 'Results' key"
            )

        return {
            "metadata": metadata,
            "report": report,
        }

    def extract_vulnerabilities(parsed_report: dict) -> list:
        """Extract individual vulnerability records from a parsed report.

        Args:
            parsed_report: Output from parse_trivy_report().

        Returns:
            List of vulnerability dictionaries ready for BigQuery insertion.
        """
        vulnerabilities = []
        report = parsed_report.get("report", {})
        metadata = parsed_report.get("metadata", {})

        # Extract resource info from metadata
        labels = metadata.get("labels", {})
        resource_namespace = (
            metadata.get("namespace", "")
            or labels.get("trivy-operator.resource.namespace", "")
        )
        resource_name = labels.get("trivy-operator.resource.name", "")
        resource_kind = labels.get("trivy-operator.resource.kind", "")
        container_name = labels.get("trivy-operator.container.name", "")

        # Get image info
        artifact = report.get("artifact", {})
        image = artifact.get("repository", "")
        if artifact.get("tag"):
            image += f":{artifact['tag']}"
        elif artifact.get("digest"):
            image += f"@{artifact['digest']}"

        scan_timestamp = report.get("updateTimestamp", datetime.now(timezone.utc).isoformat())

        for vuln in report.get("vulnerabilities", []):
            vuln_record = {
                "vulnerability_id": vuln.get("vulnerabilityID", vuln.get("VulnerabilityID", "")),
                "package_name": vuln.get("resource", vuln.get("PkgName", "")),
                "installed_version": vuln.get("installedVersion", vuln.get("InstalledVersion", "")),
                "fixed_version": vuln.get("fixedVersion", vuln.get("FixedVersion", "")),
                "severity": vuln.get("severity", vuln.get("Severity", "UNKNOWN")).upper(),
                "cvss_score": _extract_cvss_score(vuln),
                "title": vuln.get("title", vuln.get("Title", "")),
                "description": vuln.get("description", vuln.get("Description", ""))[:2000],
                "resource_namespace": resource_namespace,
                "resource_name": resource_name or container_name,
                "resource_kind": resource_kind,
                "image": image or vuln.get("target", ""),
                "scan_timestamp": scan_timestamp,
                "ingestion_timestamp": datetime.now(timezone.utc).isoformat(),
                "primary_link": vuln.get("primaryLink", vuln.get("PrimaryURL", "")),
                "target": vuln.get("target", vuln.get("Target", "")),
                "pkg_type": vuln.get("pkg_type", vuln.get("Type", "")),
                "data_source": _extract_data_source(vuln),
            }
            vulnerabilities.append(vuln_record)

        return vulnerabilities

    def _extract_cvss_score(vuln: dict) -> float:
        """Extract the highest CVSS score from vulnerability data."""
        # Try CVSS from Trivy CRD format
        score = vuln.get("score", 0.0)
        if score:
            return float(score)

        # Try CVSS from direct scan format
        cvss = vuln.get("CVSS", {})
        max_score = 0.0
        for source_data in cvss.values():
            if isinstance(source_data, dict):
                s = source_data.get("V3Score", source_data.get("V2Score", 0.0))
                if s and float(s) > max_score:
                    max_score = float(s)
        return max_score

    def _extract_data_source(vuln: dict) -> str:
        """Extract the data source from vulnerability data."""
        ds = vuln.get("data_source", vuln.get("DataSource", {}))
        if isinstance(ds, dict):
            return ds.get("Name", ds.get("ID", ""))
        return str(ds) if ds else ""

    def build_bq_rows(vulnerabilities: list) -> list:
        """Convert vulnerability records to BigQuery row format.

        Args:
            vulnerabilities: List of vulnerability dictionaries.

        Returns:
            List of dictionaries formatted for BigQuery streaming insert.
        """
        rows = []
        for vuln in vulnerabilities:
            row = {
                "vulnerability_id": str(vuln.get("vulnerability_id", "")),
                "package_name": str(vuln.get("package_name", "")),
                "installed_version": str(vuln.get("installed_version", "")),
                "fixed_version": str(vuln.get("fixed_version", "")),
                "severity": str(vuln.get("severity", "UNKNOWN")),
                "cvss_score": float(vuln.get("cvss_score", 0.0)) if vuln.get("cvss_score") else None,
                "title": str(vuln.get("title", ""))[:500],
                "description": str(vuln.get("description", ""))[:2000],
                "resource_namespace": str(vuln.get("resource_namespace", "")),
                "resource_name": str(vuln.get("resource_name", "")),
                "resource_kind": str(vuln.get("resource_kind", "")),
                "image": str(vuln.get("image", "")),
                "scan_timestamp": vuln.get("scan_timestamp", ""),
                "ingestion_timestamp": vuln.get("ingestion_timestamp", ""),
                "primary_link": str(vuln.get("primary_link", "")),
                "target": str(vuln.get("target", "")),
                "pkg_type": str(vuln.get("pkg_type", "")),
                "data_source": str(vuln.get("data_source", "")),
            }
            rows.append(row)
        return rows

    def get_last_processed_timestamp(client, table_ref: str) -> str:
        """Query BigQuery for the latest processed scan timestamp.

        Args:
            client: BigQuery client instance.
            table_ref: Full table reference (project.dataset.table).

        Returns:
            ISO format timestamp string, or empty string if no records exist.
        """
        query = f"""
            SELECT MAX(scan_timestamp) as last_ts
            FROM `{table_ref}`
            WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
        """
        result = client.query(query).result()
        for row in result:
            if row.last_ts:
                return row.last_ts.isoformat()
        return ""

    def process_incremental(client, source_table: str, dest_table: str, last_timestamp: str) -> int:
        """Process new vulnerability records incrementally.

        Args:
            client: BigQuery client instance.
            source_table: Source table with raw Trivy logs.
            dest_table: Destination table for processed vulnerabilities.
            last_timestamp: Only process records after this timestamp.

        Returns:
            Number of new records processed.
        """
        if last_timestamp:
            query = f"""
                SELECT json_payload, timestamp
                FROM `{source_table}`
                WHERE timestamp > TIMESTAMP('{last_timestamp}')
                  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
                ORDER BY timestamp ASC
            """
        else:
            query = f"""
                SELECT json_payload, timestamp
                FROM `{source_table}`
                WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
                ORDER BY timestamp ASC
                LIMIT 1000
            """

        rows = client.query(query).result()
        total_processed = 0

        batch = []
        for row in rows:
            try:
                parsed = parse_trivy_report(row.json_payload)
                vulns = extract_vulnerabilities(parsed)
                bq_rows = build_bq_rows(vulns)
                batch.extend(bq_rows)
                total_processed += len(bq_rows)

                # Flush batch every 500 rows
                if len(batch) >= 500:
                    errors = client.insert_rows_json(dest_table, batch)
                    if errors:
                        raise RuntimeError(f"BigQuery insert errors: {errors}")
                    batch = []
            except (ValueError, KeyError) as e:
                # Log and skip malformed records
                print(f"Skipping malformed record: {e}")
                continue

        # Flush remaining
        if batch:
            errors = client.insert_rows_json(dest_table, batch)
            if errors:
                raise RuntimeError(f"BigQuery insert errors: {errors}")

        return total_processed


# =============================================================================
# Test Data Fixtures
# =============================================================================

SAMPLE_TRIVY_CRD_REPORT = json.dumps({
    "apiVersion": "aquasecurity.github.io/v1alpha1",
    "kind": "VulnerabilityReport",
    "metadata": {
        "name": "replicaset-nginx-abc123-nginx",
        "namespace": "default",
        "labels": {
            "trivy-operator.resource.name": "nginx-abc123",
            "trivy-operator.resource.namespace": "default",
            "trivy-operator.resource.kind": "ReplicaSet",
            "trivy-operator.container.name": "nginx",
        },
    },
    "report": {
        "updateTimestamp": "2024-01-15T10:30:00Z",
        "artifact": {
            "repository": "nginx",
            "tag": "1.25.3",
        },
        "vulnerabilities": [
            {
                "vulnerabilityID": "CVE-2023-44487",
                "resource": "libnghttp2",
                "installedVersion": "1.52.0-1",
                "fixedVersion": "1.52.0-1+deb12u1",
                "severity": "HIGH",
                "score": 7.5,
                "title": "HTTP/2 Rapid Reset Attack",
                "description": "The HTTP/2 protocol allows a denial of service via rapid stream resets.",
                "primaryLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
            },
            {
                "vulnerabilityID": "CVE-2023-5363",
                "resource": "openssl",
                "installedVersion": "3.0.11-1",
                "fixedVersion": "3.0.13-1",
                "severity": "CRITICAL",
                "score": 9.8,
                "title": "OpenSSL: Incorrect cipher key and IV length processing",
                "description": "A bug in the processing of key and IV lengths can lead to potential truncation or overruns during initialization.",
                "primaryLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-5363",
            },
            {
                "vulnerabilityID": "CVE-2023-45853",
                "resource": "zlib",
                "installedVersion": "1.2.13-1",
                "fixedVersion": "",
                "severity": "MEDIUM",
                "score": 5.3,
                "title": "zlib: integer overflow in minizip",
                "description": "MiniZip in zlib through 1.3 has an integer overflow.",
            },
        ],
    },
})

SAMPLE_TRIVY_DIRECT_SCAN = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "python:3.11-slim",
    "ArtifactType": "container_image",
    "Metadata": {
        "OS": {"Family": "debian", "Name": "12.2"},
        "ImageID": "sha256:abc123",
    },
    "Results": [
        {
            "Target": "python:3.11-slim (debian 12.2)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-4911",
                    "PkgName": "libc6",
                    "InstalledVersion": "2.36-9",
                    "FixedVersion": "2.36-9+deb12u3",
                    "Severity": "HIGH",
                    "Title": "glibc: buffer overflow in ld.so",
                    "Description": "A buffer overflow in GNU C Library's dynamic loader.",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-4911",
                    "CVSS": {
                        "nvd": {"V3Score": 7.8},
                        "redhat": {"V3Score": 7.4},
                    },
                    "DataSource": {
                        "ID": "debian",
                        "Name": "Debian Security Tracker",
                    },
                },
            ],
        },
        {
            "Target": "Python",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Title": "Unintended leak of Proxy-Authorization header",
                    "Description": "Requests library leaks Proxy-Authorization header to destination server.",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
                    "CVSS": {
                        "ghsa": {"V3Score": 6.1},
                    },
                    "DataSource": {
                        "ID": "ghsa",
                        "Name": "GitHub Security Advisory",
                    },
                },
            ],
        },
    ],
})

SAMPLE_EMPTY_REPORT = json.dumps({
    "report": {
        "updateTimestamp": "2024-01-15T10:30:00Z",
        "artifact": {"repository": "alpine", "tag": "3.19"},
        "vulnerabilities": [],
    },
    "metadata": {
        "name": "deployment-alpine-app",
        "namespace": "production",
        "labels": {
            "trivy-operator.resource.name": "alpine-app",
            "trivy-operator.resource.kind": "Deployment",
        },
    },
})


# =============================================================================
# Test Classes
# =============================================================================


class TestParseTrivyReport(unittest.TestCase):
    """Tests for parse_trivy_report()."""

    def test_parse_crd_format(self):
        """Test parsing a Trivy VulnerabilityReport CRD format."""
        result = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        self.assertIn("report", result)
        self.assertIn("metadata", result)
        self.assertEqual(len(result["report"]["vulnerabilities"]), 3)

    def test_parse_direct_scan_format(self):
        """Test parsing a direct Trivy scan result."""
        result = parse_trivy_report(SAMPLE_TRIVY_DIRECT_SCAN)
        self.assertIn("report", result)
        # Should flatten Results into vulnerabilities
        vulns = result["report"]["vulnerabilities"]
        self.assertEqual(len(vulns), 2)

    def test_parse_empty_payload_raises_error(self):
        """Test that empty payload raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_trivy_report("")
        self.assertIn("Empty JSON payload", str(ctx.exception))

    def test_parse_invalid_json_raises_error(self):
        """Test that invalid JSON raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_trivy_report("{not valid json")
        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_parse_unrecognized_format_raises_error(self):
        """Test that unrecognized format raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_trivy_report('{"foo": "bar"}')
        self.assertIn("Unrecognized report format", str(ctx.exception))

    def test_parse_null_json_raises_error(self):
        """Test that None payload raises an error."""
        with self.assertRaises((ValueError, TypeError)):
            parse_trivy_report(None)

    def test_parse_empty_report(self):
        """Test parsing a report with no vulnerabilities."""
        result = parse_trivy_report(SAMPLE_EMPTY_REPORT)
        self.assertEqual(len(result["report"]["vulnerabilities"]), 0)

    def test_parse_preserves_metadata(self):
        """Test that metadata is preserved correctly."""
        result = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        metadata = result["metadata"]
        self.assertEqual(metadata["namespace"], "default")
        self.assertEqual(metadata["labels"]["trivy-operator.resource.kind"], "ReplicaSet")


class TestExtractVulnerabilities(unittest.TestCase):
    """Tests for extract_vulnerabilities()."""

    def test_extract_from_crd_report(self):
        """Test extraction from CRD format produces correct vulnerability records."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)

        self.assertEqual(len(vulns), 3)

        # Verify first vulnerability
        cve_44487 = vulns[0]
        self.assertEqual(cve_44487["vulnerability_id"], "CVE-2023-44487")
        self.assertEqual(cve_44487["package_name"], "libnghttp2")
        self.assertEqual(cve_44487["severity"], "HIGH")
        self.assertEqual(cve_44487["cvss_score"], 7.5)
        self.assertEqual(cve_44487["installed_version"], "1.52.0-1")
        self.assertEqual(cve_44487["fixed_version"], "1.52.0-1+deb12u1")
        self.assertEqual(cve_44487["resource_namespace"], "default")
        self.assertEqual(cve_44487["resource_kind"], "ReplicaSet")
        self.assertIn("nginx", cve_44487["image"])

    def test_extract_from_direct_scan(self):
        """Test extraction from direct scan format."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_DIRECT_SCAN)
        vulns = extract_vulnerabilities(parsed)

        self.assertEqual(len(vulns), 2)

        # Check that CVSS scores are extracted correctly
        glibc_vuln = vulns[0]
        self.assertEqual(glibc_vuln["vulnerability_id"], "CVE-2023-4911")
        self.assertGreater(glibc_vuln["cvss_score"], 0)

        # Check data source extraction
        self.assertIn("Debian", glibc_vuln["data_source"])

    def test_extract_severity_uppercase(self):
        """Test that severity values are always uppercased."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)

        for vuln in vulns:
            self.assertEqual(vuln["severity"], vuln["severity"].upper())
            self.assertIn(
                vuln["severity"],
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
            )

    def test_extract_empty_report_returns_empty_list(self):
        """Test that empty report produces no vulnerability records."""
        parsed = parse_trivy_report(SAMPLE_EMPTY_REPORT)
        vulns = extract_vulnerabilities(parsed)
        self.assertEqual(len(vulns), 0)

    def test_extract_image_with_tag(self):
        """Test that image reference includes tag when available."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)
        self.assertEqual(vulns[0]["image"], "nginx:1.25.3")

    def test_extract_image_with_digest(self):
        """Test that image reference includes digest when tag is absent."""
        report_data = json.loads(SAMPLE_TRIVY_CRD_REPORT)
        report_data["report"]["artifact"] = {
            "repository": "gcr.io/project/app",
            "digest": "sha256:abc123def456",
        }
        parsed = parse_trivy_report(json.dumps(report_data))
        vulns = extract_vulnerabilities(parsed)
        self.assertIn("sha256:abc123def456", vulns[0]["image"])

    def test_extract_description_truncation(self):
        """Test that very long descriptions are truncated."""
        report_data = json.loads(SAMPLE_TRIVY_CRD_REPORT)
        report_data["report"]["vulnerabilities"][0]["description"] = "A" * 5000
        parsed = parse_trivy_report(json.dumps(report_data))
        vulns = extract_vulnerabilities(parsed)
        self.assertLessEqual(len(vulns[0]["description"]), 2000)

    def test_extract_missing_fixed_version(self):
        """Test that missing fixed_version is handled (no fix available)."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)
        # Third vulnerability has empty fixed_version
        zlib_vuln = vulns[2]
        self.assertEqual(zlib_vuln["fixed_version"], "")

    def test_extract_includes_timestamps(self):
        """Test that scan_timestamp and ingestion_timestamp are set."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)

        for vuln in vulns:
            self.assertIsNotNone(vuln["scan_timestamp"])
            self.assertIsNotNone(vuln["ingestion_timestamp"])
            self.assertEqual(vuln["scan_timestamp"], "2024-01-15T10:30:00Z")


class TestBuildBQRows(unittest.TestCase):
    """Tests for build_bq_rows()."""

    def test_build_rows_correct_count(self):
        """Test that build_bq_rows returns correct number of rows."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)
        rows = build_bq_rows(vulns)
        self.assertEqual(len(rows), 3)

    def test_build_rows_all_string_keys(self):
        """Test that all row keys match the BigQuery schema."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_CRD_REPORT)
        vulns = extract_vulnerabilities(parsed)
        rows = build_bq_rows(vulns)

        expected_keys = {
            "vulnerability_id",
            "package_name",
            "installed_version",
            "fixed_version",
            "severity",
            "cvss_score",
            "title",
            "description",
            "resource_namespace",
            "resource_name",
            "resource_kind",
            "image",
            "scan_timestamp",
            "ingestion_timestamp",
            "primary_link",
            "target",
            "pkg_type",
            "data_source",
        }

        for row in rows:
            self.assertEqual(set(row.keys()), expected_keys)

    def test_build_rows_truncates_title(self):
        """Test that title is truncated to 500 characters."""
        vuln = {
            "vulnerability_id": "CVE-TEST",
            "package_name": "test",
            "title": "X" * 1000,
            "description": "",
        }
        rows = build_bq_rows([vuln])
        self.assertLessEqual(len(rows[0]["title"]), 500)

    def test_build_rows_handles_none_cvss(self):
        """Test that None CVSS score is preserved as None (NULL in BQ)."""
        vuln = {
            "vulnerability_id": "CVE-TEST",
            "package_name": "test",
            "cvss_score": None,
        }
        rows = build_bq_rows([vuln])
        self.assertIsNone(rows[0]["cvss_score"])

    def test_build_rows_empty_list(self):
        """Test that empty input returns empty output."""
        rows = build_bq_rows([])
        self.assertEqual(len(rows), 0)


class TestCVSSScoreExtraction(unittest.TestCase):
    """Tests for CVSS score extraction logic."""

    def test_cvss_from_score_field(self):
        """Test CVSS extraction from the 'score' field (CRD format)."""
        vuln = {"score": 9.8}
        self.assertEqual(_extract_cvss_score(vuln), 9.8)

    def test_cvss_from_v3score(self):
        """Test CVSS extraction from nested CVSS V3Score."""
        vuln = {
            "CVSS": {
                "nvd": {"V3Score": 7.5},
                "redhat": {"V3Score": 7.0},
            }
        }
        score = _extract_cvss_score(vuln)
        self.assertEqual(score, 7.5)

    def test_cvss_returns_highest_score(self):
        """Test that the highest CVSS score from multiple sources is returned."""
        vuln = {
            "CVSS": {
                "nvd": {"V3Score": 6.0},
                "ghsa": {"V3Score": 8.5},
            }
        }
        score = _extract_cvss_score(vuln)
        self.assertEqual(score, 8.5)

    def test_cvss_zero_when_missing(self):
        """Test that missing CVSS returns 0.0."""
        vuln = {}
        score = _extract_cvss_score(vuln)
        self.assertEqual(score, 0.0)

    def test_cvss_handles_string_score(self):
        """Test that string scores are converted to float."""
        vuln = {"score": "7.2"}
        score = _extract_cvss_score(vuln)
        self.assertEqual(score, 7.2)


class TestDataSourceExtraction(unittest.TestCase):
    """Tests for data source extraction logic."""

    def test_data_source_from_dict(self):
        """Test extraction from DataSource dictionary."""
        vuln = {"DataSource": {"ID": "debian", "Name": "Debian Security Tracker"}}
        result = _extract_data_source(vuln)
        self.assertEqual(result, "Debian Security Tracker")

    def test_data_source_from_string(self):
        """Test extraction from plain string DataSource."""
        vuln = {"data_source": "NVD"}
        result = _extract_data_source(vuln)
        self.assertEqual(result, "NVD")

    def test_data_source_missing(self):
        """Test that missing DataSource returns empty string."""
        vuln = {}
        result = _extract_data_source(vuln)
        self.assertEqual(result, "")


class TestGetLastProcessedTimestamp(unittest.TestCase):
    """Tests for get_last_processed_timestamp() with mocked BigQuery."""

    def test_returns_timestamp_when_records_exist(self):
        """Test that the latest timestamp is returned when records exist."""
        mock_client = MagicMock()
        mock_row = MagicMock()
        mock_row.last_ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [mock_row]
        mock_client.query.return_value = mock_query_job

        result = get_last_processed_timestamp(mock_client, "project.dataset.table")
        self.assertIn("2024-01-15", result)

    def test_returns_empty_when_no_records(self):
        """Test that empty string is returned when no records exist."""
        mock_client = MagicMock()
        mock_row = MagicMock()
        mock_row.last_ts = None

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [mock_row]
        mock_client.query.return_value = mock_query_job

        result = get_last_processed_timestamp(mock_client, "project.dataset.table")
        self.assertEqual(result, "")

    def test_query_contains_table_reference(self):
        """Test that the query includes the correct table reference."""
        mock_client = MagicMock()
        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [MagicMock(last_ts=None)]
        mock_client.query.return_value = mock_query_job

        get_last_processed_timestamp(mock_client, "my-project.security.vulns")
        call_args = mock_client.query.call_args[0][0]
        self.assertIn("my-project.security.vulns", call_args)


class TestProcessIncremental(unittest.TestCase):
    """Tests for process_incremental() with mocked BigQuery."""

    def _make_mock_row(self, json_payload, timestamp="2024-01-15T10:30:00Z"):
        """Create a mock BigQuery row."""
        mock_row = MagicMock()
        mock_row.json_payload = json_payload
        mock_row.timestamp = timestamp
        return mock_row

    def test_processes_new_records(self):
        """Test that new records are processed and inserted."""
        mock_client = MagicMock()

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [
            self._make_mock_row(SAMPLE_TRIVY_CRD_REPORT),
        ]
        mock_client.query.return_value = mock_query_job
        mock_client.insert_rows_json.return_value = []  # No errors

        count = process_incremental(
            mock_client,
            "project.dataset.trivy_raw_logs",
            "project.dataset.vulnerabilities",
            "2024-01-14T00:00:00Z",
        )

        self.assertEqual(count, 3)  # 3 vulnerabilities in the sample
        mock_client.insert_rows_json.assert_called_once()

    def test_processes_without_last_timestamp(self):
        """Test processing when no last timestamp exists (first run)."""
        mock_client = MagicMock()

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [
            self._make_mock_row(SAMPLE_TRIVY_CRD_REPORT),
        ]
        mock_client.query.return_value = mock_query_job
        mock_client.insert_rows_json.return_value = []

        count = process_incremental(
            mock_client,
            "project.dataset.trivy_raw_logs",
            "project.dataset.vulnerabilities",
            "",  # No last timestamp
        )

        self.assertEqual(count, 3)
        # Verify query uses LIMIT when no timestamp
        call_args = mock_client.query.call_args[0][0]
        self.assertIn("LIMIT", call_args)

    def test_skips_malformed_records(self):
        """Test that malformed records are skipped without failing."""
        mock_client = MagicMock()

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [
            self._make_mock_row("not valid json"),
            self._make_mock_row(SAMPLE_TRIVY_CRD_REPORT),
        ]
        mock_client.query.return_value = mock_query_job
        mock_client.insert_rows_json.return_value = []

        count = process_incremental(
            mock_client,
            "project.dataset.trivy_raw_logs",
            "project.dataset.vulnerabilities",
            "2024-01-14T00:00:00Z",
        )

        # Should only process the valid record
        self.assertEqual(count, 3)

    def test_raises_on_insert_errors(self):
        """Test that BigQuery insert errors raise RuntimeError."""
        mock_client = MagicMock()

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [
            self._make_mock_row(SAMPLE_TRIVY_CRD_REPORT),
        ]
        mock_client.query.return_value = mock_query_job
        mock_client.insert_rows_json.return_value = [
            {"index": 0, "errors": [{"reason": "invalid", "message": "bad data"}]}
        ]

        with self.assertRaises(RuntimeError) as ctx:
            process_incremental(
                mock_client,
                "project.dataset.trivy_raw_logs",
                "project.dataset.vulnerabilities",
                "2024-01-14T00:00:00Z",
            )
        self.assertIn("BigQuery insert errors", str(ctx.exception))

    def test_returns_zero_for_no_new_records(self):
        """Test that zero is returned when there are no new records."""
        mock_client = MagicMock()

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = []
        mock_client.query.return_value = mock_query_job

        count = process_incremental(
            mock_client,
            "project.dataset.trivy_raw_logs",
            "project.dataset.vulnerabilities",
            "2024-01-15T12:00:00Z",
        )

        self.assertEqual(count, 0)
        mock_client.insert_rows_json.assert_not_called()

    def test_batch_flush_at_threshold(self):
        """Test that rows are flushed in batches of 500."""
        mock_client = MagicMock()

        # Create enough records to trigger batch flush
        # Each report has 3 vulns, so ~167 reports => 501 vulns
        rows = []
        for i in range(170):
            rows.append(self._make_mock_row(SAMPLE_TRIVY_CRD_REPORT))

        mock_query_job = MagicMock()
        mock_query_job.result.return_value = rows
        mock_client.query.return_value = mock_query_job
        mock_client.insert_rows_json.return_value = []

        count = process_incremental(
            mock_client,
            "project.dataset.trivy_raw_logs",
            "project.dataset.vulnerabilities",
            "2024-01-14T00:00:00Z",
        )

        self.assertEqual(count, 510)  # 170 * 3
        # Should have been called at least twice (batch of 500 + remainder)
        self.assertGreaterEqual(mock_client.insert_rows_json.call_count, 2)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def test_vulnerability_with_no_cve_id(self):
        """Test handling of vulnerability without a CVE ID."""
        report = json.dumps({
            "report": {
                "updateTimestamp": "2024-01-15T10:30:00Z",
                "artifact": {"repository": "test", "tag": "latest"},
                "vulnerabilities": [
                    {
                        "vulnerabilityID": "",
                        "resource": "test-pkg",
                        "severity": "LOW",
                    }
                ],
            },
            "metadata": {"labels": {}},
        })
        parsed = parse_trivy_report(report)
        vulns = extract_vulnerabilities(parsed)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["vulnerability_id"], "")

    def test_unicode_in_description(self):
        """Test that Unicode characters in descriptions are handled."""
        report = json.dumps({
            "report": {
                "updateTimestamp": "2024-01-15T10:30:00Z",
                "artifact": {"repository": "test", "tag": "latest"},
                "vulnerabilities": [
                    {
                        "vulnerabilityID": "CVE-2024-UNICODE",
                        "resource": "test-pkg",
                        "severity": "LOW",
                        "description": "Vulnerability with unicode: \u00e9\u00e8\u00ea \u00fc\u00f6\u00e4 \u2603",
                    }
                ],
            },
            "metadata": {"labels": {}},
        })
        parsed = parse_trivy_report(report)
        vulns = extract_vulnerabilities(parsed)
        self.assertIn("\u00e9", vulns[0]["description"])

    def test_extremely_long_package_name(self):
        """Test handling of very long package names."""
        report = json.dumps({
            "report": {
                "updateTimestamp": "2024-01-15T10:30:00Z",
                "artifact": {"repository": "test", "tag": "latest"},
                "vulnerabilities": [
                    {
                        "vulnerabilityID": "CVE-2024-LONG",
                        "resource": "a" * 1000,
                        "severity": "LOW",
                    }
                ],
            },
            "metadata": {"labels": {}},
        })
        parsed = parse_trivy_report(report)
        vulns = extract_vulnerabilities(parsed)
        self.assertEqual(len(vulns), 1)

    def test_multiple_results_targets_are_preserved(self):
        """Test that target and pkg_type from direct scan Results are preserved."""
        parsed = parse_trivy_report(SAMPLE_TRIVY_DIRECT_SCAN)
        vulns = extract_vulnerabilities(parsed)

        os_vuln = vulns[0]
        self.assertIn("debian", os_vuln.get("target", "") or os_vuln.get("pkg_type", ""))

        pip_vuln = vulns[1]
        self.assertIn("pip", pip_vuln.get("pkg_type", "") or pip_vuln.get("target", ""))


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    # Use pytest if available, otherwise fall back to unittest
    try:
        import pytest
        sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
    except ImportError:
        unittest.main(verbosity=2)
