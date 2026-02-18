#!/usr/bin/env python3
"""Extract vulnerability data from raw Trivy logs in BigQuery.

This script reads raw Trivy Operator log entries from the trivy_raw_logs
BigQuery table, parses the JSON payload to extract individual vulnerability
findings from VulnerabilityReport CRD format, and writes structured records
to the vulnerabilities table.

The script supports incremental processing by tracking the last processed
timestamp, a dry-run mode for validation, and configurable date ranges.

Usage:
    # Process all unprocessed logs
    python extract_vulnerabilities.py --project-id my-project --dataset trivy_data

    # Process a specific date range
    python extract_vulnerabilities.py \\
        --project-id my-project \\
        --dataset trivy_data \\
        --start-date 2025-01-01 \\
        --end-date 2025-01-31

    # Dry run to preview without writing
    python extract_vulnerabilities.py \\
        --project-id my-project \\
        --dataset trivy_data \\
        --dry-run

    # Process with custom batch size and verbose logging
    python extract_vulnerabilities.py \\
        --project-id my-project \\
        --dataset trivy_data \\
        --batch-size 500 \\
        --log-level DEBUG
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from google.api_core import exceptions as gcp_exceptions
from google.api_core import retry as gcp_retry
from google.cloud import bigquery

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_RAW_TABLE = "trivy_raw_logs"
DEFAULT_VULN_TABLE = "vulnerabilities"
DEFAULT_BATCH_SIZE = 1000
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class VulnerabilityRecord:
    """A single parsed vulnerability finding."""

    vulnerability_id: str
    package_name: str
    installed_version: Optional[str]
    fixed_version: Optional[str]
    severity: str
    cvss_score: Optional[float]
    title: Optional[str]
    description: Optional[str]
    resource_namespace: Optional[str]
    resource_name: Optional[str]
    resource_kind: Optional[str]
    image: Optional[str]
    scan_timestamp: datetime
    ingestion_timestamp: datetime
    primary_link: Optional[str] = None
    target: Optional[str] = None
    pkg_type: Optional[str] = None
    data_source: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary suitable for BigQuery insertion."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "title": self.title,
            "description": self.description,
            "resource_namespace": self.resource_namespace,
            "resource_name": self.resource_name,
            "resource_kind": self.resource_kind,
            "image": self.image,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "ingestion_timestamp": self.ingestion_timestamp.isoformat(),
            "primary_link": self.primary_link,
            "target": self.target,
            "pkg_type": self.pkg_type,
            "data_source": self.data_source,
        }


@dataclass
class ExtractionStats:
    """Tracks statistics for a single extraction run."""

    raw_rows_read: int = 0
    raw_rows_skipped: int = 0
    vulnerabilities_extracted: int = 0
    vulnerabilities_written: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.monotonic)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    def summary(self) -> str:
        return (
            f"Extraction complete in {self.elapsed_seconds:.1f}s | "
            f"Raw rows read: {self.raw_rows_read} | "
            f"Skipped: {self.raw_rows_skipped} | "
            f"Vulnerabilities extracted: {self.vulnerabilities_extracted} | "
            f"Written: {self.vulnerabilities_written} | "
            f"Errors: {self.errors}"
        )


# ---------------------------------------------------------------------------
# Parsing logic
# ---------------------------------------------------------------------------
def parse_trivy_report(
    json_payload: str,
    scan_timestamp: datetime,
    ingestion_ts: datetime,
) -> list[VulnerabilityRecord]:
    """Parse a Trivy VulnerabilityReport JSON payload into vulnerability records.

    The expected format is the Trivy Operator VulnerabilityReport CRD, which
    has the structure:

        {
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": "VulnerabilityReport",
            "metadata": { ... },
            "report": {
                "artifact": { "repository": "...", "tag": "..." },
                "vulnerabilities": [ ... ]
            }
        }

    It also handles the case where the payload is just the report section
    or a list of vulnerabilities directly.

    Args:
        json_payload: Raw JSON string from the log entry.
        scan_timestamp: Timestamp of the scan from the log entry.
        ingestion_ts: Current timestamp for ingestion tracking.

    Returns:
        A list of VulnerabilityRecord objects extracted from the payload.
    """
    records: list[VulnerabilityRecord] = []

    try:
        data = json.loads(json_payload)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Failed to parse JSON payload: %s", exc)
        return records

    # Navigate to the report section based on format
    report = _extract_report_section(data)
    if report is None:
        logger.debug("No report section found in payload, skipping.")
        return records

    # Extract resource metadata from the CRD metadata or report
    metadata = data.get("metadata", {})
    labels = metadata.get("labels", {})

    resource_namespace = (
        metadata.get("namespace")
        or labels.get("trivy-operator.resource.namespace")
    )
    resource_name = labels.get("trivy-operator.resource.name")
    resource_kind = labels.get("trivy-operator.resource.kind")

    # Extract image information from the report artifact
    artifact = report.get("artifact", {})
    image = _build_image_reference(artifact)

    # Parse each vulnerability entry
    vulnerabilities = report.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        logger.warning(
            "Expected 'vulnerabilities' to be a list, got %s",
            type(vulnerabilities).__name__,
        )
        return records

    for vuln in vulnerabilities:
        record = _parse_single_vulnerability(
            vuln=vuln,
            resource_namespace=resource_namespace,
            resource_name=resource_name,
            resource_kind=resource_kind,
            image=image,
            scan_timestamp=scan_timestamp,
            ingestion_ts=ingestion_ts,
        )
        if record is not None:
            records.append(record)

    return records


def _extract_report_section(data: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Locate the report section in different payload formats.

    Args:
        data: The parsed JSON data.

    Returns:
        The report dictionary, or None if not found.
    """
    # Full CRD format: { "kind": "VulnerabilityReport", "report": { ... } }
    if "report" in data:
        return data["report"]

    # Direct report format: { "artifact": { ... }, "vulnerabilities": [ ... ] }
    if "vulnerabilities" in data and "artifact" in data:
        return data

    # Wrapped in a status field (some operator versions)
    if "status" in data and isinstance(data["status"], dict):
        status = data["status"]
        if "vulnerabilities" in status:
            return status

    return None


def _build_image_reference(artifact: dict[str, Any]) -> Optional[str]:
    """Build a full container image reference from the artifact section.

    Args:
        artifact: The artifact dictionary from the report.

    Returns:
        A string like 'registry/repo:tag' or 'registry/repo@sha256:...',
        or None if the artifact data is insufficient.
    """
    repository = artifact.get("repository")
    if not repository:
        return None

    registry = artifact.get("registry")
    tag = artifact.get("tag")
    digest = artifact.get("digest")

    parts = []
    if registry:
        parts.append(f"{registry}/{repository}")
    else:
        parts.append(repository)

    image_ref = parts[0]
    if digest:
        image_ref = f"{image_ref}@{digest}"
    elif tag:
        image_ref = f"{image_ref}:{tag}"

    return image_ref


def _parse_single_vulnerability(
    vuln: dict[str, Any],
    resource_namespace: Optional[str],
    resource_name: Optional[str],
    resource_kind: Optional[str],
    image: Optional[str],
    scan_timestamp: datetime,
    ingestion_ts: datetime,
) -> Optional[VulnerabilityRecord]:
    """Parse a single vulnerability entry from the report.

    Args:
        vuln: A single vulnerability dictionary from the report.
        resource_namespace: Namespace of the scanned resource.
        resource_name: Name of the scanned resource.
        resource_kind: Kind of the scanned resource.
        image: Container image reference.
        scan_timestamp: When the scan was performed.
        ingestion_ts: When this record is being ingested.

    Returns:
        A VulnerabilityRecord, or None if required fields are missing.
    """
    vuln_id = vuln.get("vulnerabilityID")
    pkg_name = vuln.get("resource") or vuln.get("packageName")
    severity = vuln.get("severity", "UNKNOWN")

    if not vuln_id or not pkg_name:
        logger.debug(
            "Skipping vulnerability entry with missing ID or package name: %s",
            vuln,
        )
        return None

    # Normalize severity to upper case
    severity = severity.upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        logger.debug("Non-standard severity '%s', mapping to UNKNOWN", severity)
        severity = "UNKNOWN"

    # Extract CVSS score - try multiple possible locations
    cvss_score = _extract_cvss_score(vuln)

    # Extract primary link
    links = vuln.get("links", [])
    primary_link = vuln.get("primaryLink")
    if not primary_link and isinstance(links, list) and links:
        primary_link = links[0] if isinstance(links[0], str) else None

    return VulnerabilityRecord(
        vulnerability_id=vuln_id,
        package_name=pkg_name,
        installed_version=vuln.get("installedVersion"),
        fixed_version=vuln.get("fixedVersion"),
        severity=severity,
        cvss_score=cvss_score,
        title=vuln.get("title"),
        description=_truncate(vuln.get("description"), max_length=10000),
        resource_namespace=resource_namespace,
        resource_name=resource_name,
        resource_kind=resource_kind,
        image=image,
        scan_timestamp=scan_timestamp,
        ingestion_timestamp=ingestion_ts,
        primary_link=primary_link,
        target=vuln.get("target"),
        pkg_type=vuln.get("pkgType") or vuln.get("class"),
        data_source=vuln.get("dataSource"),
    )


def _extract_cvss_score(vuln: dict[str, Any]) -> Optional[float]:
    """Extract the CVSS score from a vulnerability entry.

    Trivy reports may store the score in different fields depending on
    the version and configuration.

    Args:
        vuln: The vulnerability dictionary.

    Returns:
        The CVSS score as a float, or None if not available.
    """
    # Direct score field
    score = vuln.get("score")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass

    # Nested under CVSS v3
    cvss = vuln.get("cvss", {})
    if isinstance(cvss, dict):
        for key in ("nvd", "redhat", "ghsa"):
            entry = cvss.get(key, {})
            if isinstance(entry, dict):
                v3_score = entry.get("V3Score")
                if v3_score is not None:
                    try:
                        return float(v3_score)
                    except (ValueError, TypeError):
                        continue

    return None


def _truncate(text: Optional[str], max_length: int = 10000) -> Optional[str]:
    """Truncate text to a maximum length if necessary.

    Args:
        text: The text to truncate, or None.
        max_length: Maximum allowed length.

    Returns:
        The truncated text or None.
    """
    if text is None:
        return None
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


# ---------------------------------------------------------------------------
# BigQuery operations
# ---------------------------------------------------------------------------
class BigQueryExtractor:
    """Manages reading raw logs and writing vulnerability records to BigQuery.

    Attributes:
        client: BigQuery client instance.
        project_id: GCP project ID.
        dataset: BigQuery dataset name.
        raw_table: Name of the raw logs table.
        vuln_table: Name of the vulnerabilities table.
        dry_run: If True, do not write to BigQuery.
        batch_size: Number of rows to insert per batch.
    """

    def __init__(
        self,
        project_id: str,
        dataset: str,
        raw_table: str = DEFAULT_RAW_TABLE,
        vuln_table: str = DEFAULT_VULN_TABLE,
        dry_run: bool = False,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        self.project_id = project_id
        self.dataset = dataset
        self.raw_table = raw_table
        self.vuln_table = vuln_table
        self.dry_run = dry_run
        self.batch_size = batch_size

        self.client = bigquery.Client(project=project_id)

        self._raw_table_ref = f"{project_id}.{dataset}.{raw_table}"
        self._vuln_table_ref = f"{project_id}.{dataset}.{vuln_table}"

    def get_last_processed_timestamp(self) -> Optional[datetime]:
        """Retrieve the most recent scan_timestamp from the vulnerabilities table.

        This enables incremental processing by only reading raw log entries
        newer than the last successfully processed timestamp.

        Returns:
            The latest scan_timestamp, or None if the table is empty or
            does not exist.
        """
        query = f"""
            SELECT MAX(scan_timestamp) AS last_ts
            FROM `{self._vuln_table_ref}`
            WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY)
        """
        try:
            result = self.client.query(query).result()
            for row in result:
                if row.last_ts is not None:
                    logger.info("Last processed timestamp: %s", row.last_ts)
                    return row.last_ts
        except gcp_exceptions.NotFound:
            logger.warning(
                "Vulnerabilities table %s not found. "
                "Will process all available raw logs.",
                self._vuln_table_ref,
            )
        except gcp_exceptions.BadRequest as exc:
            logger.warning(
                "Error querying last processed timestamp: %s. "
                "Will process all available raw logs.",
                exc,
            )

        logger.info("No previously processed data found.")
        return None

    def read_raw_logs(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        last_processed_ts: Optional[datetime] = None,
    ) -> bigquery.table.RowIterator:
        """Read raw Trivy log entries from BigQuery.

        Builds a query with appropriate partition and time filters for
        efficient scanning.

        Args:
            start_date: Start date for filtering (YYYY-MM-DD). Inclusive.
            end_date: End date for filtering (YYYY-MM-DD). Inclusive.
            last_processed_ts: Only read entries newer than this timestamp.

        Returns:
            An iterator of BigQuery row results.
        """
        conditions: list[str] = []
        query_params: list[bigquery.ScalarQueryParameter] = []

        # Partition filter is always required by our table config
        if start_date:
            conditions.append("DATE(timestamp) >= @start_date")
            query_params.append(
                bigquery.ScalarQueryParameter("start_date", "DATE", start_date)
            )
        elif last_processed_ts:
            # Use the day before last_processed as a safety margin
            conditions.append("DATE(timestamp) >= DATE_SUB(DATE(@last_ts), INTERVAL 1 DAY)")
            query_params.append(
                bigquery.ScalarQueryParameter(
                    "last_ts", "TIMESTAMP", last_processed_ts
                )
            )
        else:
            # Default: last 30 days
            conditions.append(
                "DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)"
            )

        if end_date:
            conditions.append("DATE(timestamp) <= @end_date")
            query_params.append(
                bigquery.ScalarQueryParameter("end_date", "DATE", end_date)
            )

        if last_processed_ts and not start_date:
            conditions.append("timestamp > @last_ts_filter")
            query_params.append(
                bigquery.ScalarQueryParameter(
                    "last_ts_filter", "TIMESTAMP", last_processed_ts
                )
            )

        # Only process entries that contain JSON payload data
        conditions.append("json_payload IS NOT NULL")
        conditions.append("TRIM(json_payload) != ''")

        where_clause = " AND ".join(conditions)

        query = f"""
            SELECT
                timestamp,
                severity,
                insert_id,
                resource,
                json_payload
            FROM `{self._raw_table_ref}`
            WHERE {where_clause}
            ORDER BY timestamp ASC
        """

        job_config = bigquery.QueryJobConfig(query_parameters=query_params)

        logger.info("Executing raw log query with filters: %s", where_clause)
        logger.debug("Full query:\n%s", query)

        return self.client.query(query, job_config=job_config).result()

    def write_vulnerabilities(
        self,
        records: list[VulnerabilityRecord],
        stats: ExtractionStats,
    ) -> None:
        """Write a batch of vulnerability records to BigQuery.

        Uses the streaming insert API for low-latency ingestion. Implements
        retry logic for transient failures.

        Args:
            records: List of VulnerabilityRecord objects to insert.
            stats: Extraction statistics tracker.
        """
        if not records:
            logger.debug("No records to write in this batch.")
            return

        if self.dry_run:
            logger.info(
                "[DRY RUN] Would write %d vulnerability records.", len(records)
            )
            stats.vulnerabilities_written += len(records)
            return

        rows = [r.to_dict() for r in records]
        table_ref = self.client.get_table(self._vuln_table_ref)

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                errors = self.client.insert_rows_json(
                    table_ref,
                    rows,
                    retry=gcp_retry.Retry(deadline=60),
                )

                if errors:
                    logger.error(
                        "BigQuery streaming insert errors (attempt %d/%d): %s",
                        attempt,
                        MAX_RETRIES,
                        errors,
                    )
                    stats.errors += len(errors)
                    if attempt < MAX_RETRIES:
                        time.sleep(RETRY_DELAY_SECONDS * attempt)
                        continue
                    else:
                        logger.error(
                            "Failed to write %d records after %d attempts.",
                            len(rows),
                            MAX_RETRIES,
                        )
                        return
                else:
                    stats.vulnerabilities_written += len(rows)
                    logger.info(
                        "Successfully wrote %d vulnerability records.", len(rows)
                    )
                    return

            except gcp_exceptions.GoogleAPICallError as exc:
                logger.error(
                    "BigQuery API error on attempt %d/%d: %s",
                    attempt,
                    MAX_RETRIES,
                    exc,
                )
                stats.errors += 1
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY_SECONDS * attempt)
                else:
                    raise

    def run_extraction(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> ExtractionStats:
        """Execute the full extraction pipeline.

        Reads raw Trivy logs, parses vulnerability data, and writes results
        to the vulnerabilities table. Supports incremental processing and
        batched writes.

        Args:
            start_date: Optional start date filter (YYYY-MM-DD).
            end_date: Optional end date filter (YYYY-MM-DD).

        Returns:
            ExtractionStats with counts and timing information.
        """
        stats = ExtractionStats()

        # Determine incremental processing point
        last_processed_ts: Optional[datetime] = None
        if not start_date:
            last_processed_ts = self.get_last_processed_timestamp()

        # Read raw logs
        logger.info("Reading raw Trivy logs from %s ...", self._raw_table_ref)
        rows = self.read_raw_logs(
            start_date=start_date,
            end_date=end_date,
            last_processed_ts=last_processed_ts,
        )

        # Process rows in batches
        batch: list[VulnerabilityRecord] = []
        ingestion_ts = datetime.now(timezone.utc)

        for row in rows:
            stats.raw_rows_read += 1

            if stats.raw_rows_read % 1000 == 0:
                logger.info(
                    "Processing progress: %d raw rows read, %d vulnerabilities extracted",
                    stats.raw_rows_read,
                    stats.vulnerabilities_extracted,
                )

            scan_timestamp = row.timestamp
            json_payload = row.json_payload

            if not json_payload:
                stats.raw_rows_skipped += 1
                continue

            try:
                records = parse_trivy_report(
                    json_payload=json_payload,
                    scan_timestamp=scan_timestamp,
                    ingestion_ts=ingestion_ts,
                )
            except Exception as exc:
                logger.error(
                    "Unexpected error parsing row (insert_id=%s): %s",
                    row.insert_id,
                    exc,
                    exc_info=True,
                )
                stats.errors += 1
                stats.raw_rows_skipped += 1
                continue

            if not records:
                stats.raw_rows_skipped += 1
                continue

            stats.vulnerabilities_extracted += len(records)
            batch.extend(records)

            # Flush batch when it reaches the configured size
            if len(batch) >= self.batch_size:
                self.write_vulnerabilities(batch, stats)
                batch = []

        # Flush remaining records
        if batch:
            self.write_vulnerabilities(batch, stats)

        logger.info(stats.summary())
        return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Argument list to parse. Defaults to sys.argv[1:].

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Extract vulnerability data from raw Trivy Operator logs "
            "in BigQuery and write structured records to the "
            "vulnerabilities table."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all unprocessed logs (incremental)
  %(prog)s --project-id my-project --dataset trivy_data

  # Process a specific date range
  %(prog)s --project-id my-project --dataset trivy_data \\
           --start-date 2025-01-01 --end-date 2025-01-31

  # Dry run
  %(prog)s --project-id my-project --dataset trivy_data --dry-run
        """,
    )

    parser.add_argument(
        "--project-id",
        required=True,
        help="GCP project ID containing the BigQuery dataset.",
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="BigQuery dataset name (e.g., trivy_data).",
    )
    parser.add_argument(
        "--raw-table",
        default=DEFAULT_RAW_TABLE,
        help=f"Name of the raw logs table (default: {DEFAULT_RAW_TABLE}).",
    )
    parser.add_argument(
        "--vuln-table",
        default=DEFAULT_VULN_TABLE,
        help=f"Name of the vulnerabilities table (default: {DEFAULT_VULN_TABLE}).",
    )
    parser.add_argument(
        "--start-date",
        default=None,
        help="Start date for processing (YYYY-MM-DD). Inclusive.",
    )
    parser.add_argument(
        "--end-date",
        default=None,
        help="End date for processing (YYYY-MM-DD). Inclusive.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Number of records per BigQuery insert batch (default: {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate without writing to BigQuery.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level (default: INFO).",
    )

    return parser.parse_args(argv)


def configure_logging(level: str) -> None:
    """Configure structured logging for the extraction script.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    log_format = (
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=log_format,
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stdout,
    )

    # Suppress noisy third-party loggers
    logging.getLogger("google.auth").setLevel(logging.WARNING)
    logging.getLogger("google.cloud").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point for the extraction script.

    Args:
        argv: Command-line argument list. Defaults to sys.argv[1:].

    Returns:
        Exit code: 0 for success, 1 for errors.
    """
    args = parse_args(argv)
    configure_logging(args.log_level)

    logger.info("=" * 72)
    logger.info("Trivy Vulnerability Extraction")
    logger.info("=" * 72)
    logger.info("Project:    %s", args.project_id)
    logger.info("Dataset:    %s", args.dataset)
    logger.info("Raw table:  %s", args.raw_table)
    logger.info("Vuln table: %s", args.vuln_table)
    logger.info("Batch size: %d", args.batch_size)
    logger.info("Dry run:    %s", args.dry_run)
    logger.info("Date range: %s to %s", args.start_date or "auto", args.end_date or "now")
    logger.info("=" * 72)

    try:
        extractor = BigQueryExtractor(
            project_id=args.project_id,
            dataset=args.dataset,
            raw_table=args.raw_table,
            vuln_table=args.vuln_table,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
        )

        stats = extractor.run_extraction(
            start_date=args.start_date,
            end_date=args.end_date,
        )

        if stats.errors > 0:
            logger.warning(
                "Extraction completed with %d error(s). Review logs for details.",
                stats.errors,
            )
            return 1

        logger.info("Extraction completed successfully.")
        return 0

    except gcp_exceptions.GoogleAPICallError as exc:
        logger.error("BigQuery API error: %s", exc)
        return 1
    except gcp_exceptions.Forbidden as exc:
        logger.error(
            "Permission denied. Ensure the service account has "
            "BigQuery Data Editor and Job User roles: %s",
            exc,
        )
        return 1
    except Exception as exc:
        logger.error("Unexpected error: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
