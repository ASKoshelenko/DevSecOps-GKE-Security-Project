-- =============================================================================
-- BigQuery DDL: Trivy Vulnerability Scanning Tables
-- =============================================================================
-- This script creates the tables required for storing and analyzing
-- vulnerability scan data from Trivy Operator running on GKE.
--
-- Tables:
--   1. trivy_raw_logs    - Raw log entries from the Cloud Logging sink
--   2. vulnerabilities   - Parsed and structured vulnerability records
--
-- Usage:
--   Replace ${PROJECT_ID} and ${DATASET} with your actual values, then
--   execute in the BigQuery console or via the bq CLI:
--
--     bq query --use_legacy_sql=false --project_id=<PROJECT_ID> < create_tables.sql
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: trivy_raw_logs
-- -----------------------------------------------------------------------------
-- Stores raw Trivy Operator log entries as they arrive from the Cloud Logging
-- log sink. Partitioned by day on the timestamp column for cost-efficient
-- querying. Clustered by severity and resource labels to accelerate common
-- filter patterns.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.${DATASET}.trivy_raw_logs`
(
    timestamp         TIMESTAMP   NOT NULL
        OPTIONS(description = 'Timestamp when the log entry was created in Cloud Logging'),

    severity          STRING
        OPTIONS(description = 'Log entry severity level (INFO, WARNING, ERROR, etc.)'),

    insert_id         STRING
        OPTIONS(description = 'Unique identifier for the log entry, used for deduplication'),

    log_name          STRING
        OPTIONS(description = 'Full resource name of the log this entry belongs to'),

    resource          STRUCT<
        type            STRING,
        labels          STRUCT<
            project_id      STRING,
            cluster_name    STRING,
            namespace_name  STRING,
            container_name  STRING,
            pod_name        STRING,
            location        STRING
        >
    >
        OPTIONS(description = 'Monitored resource that produced this log entry'),

    labels            STRUCT<
        k8s_pod_app              STRING,
        k8s_pod_controller_kind  STRING,
        k8s_pod_controller_name  STRING
    >
        OPTIONS(description = 'User-defined labels attached to the log entry'),

    json_payload      STRING
        OPTIONS(description = 'Raw JSON payload containing the Trivy VulnerabilityReport CRD data'),

    receive_timestamp TIMESTAMP
        OPTIONS(description = 'Timestamp when the log entry was received by Cloud Logging'),

    trace             STRING
        OPTIONS(description = 'Resource name of the trace associated with the log entry'),

    span_id           STRING
        OPTIONS(description = 'Span ID within the trace associated with the log entry')
)
PARTITION BY DATE(timestamp)
CLUSTER BY severity, resource.labels.namespace_name, resource.labels.cluster_name
OPTIONS(
    description = 'Raw Trivy Operator log entries from Cloud Logging sink. Partitioned by day on timestamp, clustered by severity and resource namespace/cluster.',
    labels = [('team', 'devsecops'), ('data_classification', 'internal')],
    require_partition_filter = TRUE
);


-- -----------------------------------------------------------------------------
-- Table: vulnerabilities
-- -----------------------------------------------------------------------------
-- Stores parsed vulnerability records extracted from the raw Trivy logs.
-- Each row represents a single vulnerability finding in a specific container
-- image. Partitioned by day on scan_timestamp and clustered by severity and
-- image to optimize common analytical query patterns.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.${DATASET}.vulnerabilities`
(
    vulnerability_id    STRING      NOT NULL
        OPTIONS(description = 'CVE or vulnerability identifier (e.g., CVE-2023-12345)'),

    package_name        STRING      NOT NULL
        OPTIONS(description = 'Name of the affected software package'),

    installed_version   STRING
        OPTIONS(description = 'Currently installed version of the package'),

    fixed_version       STRING
        OPTIONS(description = 'Version containing the fix; NULL if no fix is available'),

    severity            STRING      NOT NULL
        OPTIONS(description = 'Vulnerability severity: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN'),

    cvss_score          FLOAT64
        OPTIONS(description = 'CVSS v3 base score (0.0 - 10.0)'),

    title               STRING
        OPTIONS(description = 'Short title or summary of the vulnerability'),

    description         STRING
        OPTIONS(description = 'Detailed description of the vulnerability'),

    resource_namespace  STRING
        OPTIONS(description = 'Kubernetes namespace of the scanned resource'),

    resource_name       STRING
        OPTIONS(description = 'Name of the scanned Kubernetes resource'),

    resource_kind       STRING
        OPTIONS(description = 'Kind of Kubernetes resource (Deployment, DaemonSet, etc.)'),

    image               STRING
        OPTIONS(description = 'Full container image reference including tag or digest'),

    scan_timestamp      TIMESTAMP   NOT NULL
        OPTIONS(description = 'Timestamp when the Trivy scan was performed'),

    ingestion_timestamp TIMESTAMP   NOT NULL
        OPTIONS(description = 'Timestamp when this record was ingested into the vulnerabilities table'),

    primary_link        STRING
        OPTIONS(description = 'Primary URL reference for the vulnerability advisory'),

    target              STRING
        OPTIONS(description = 'Scan target within the image (OS packages, language files, etc.)'),

    pkg_type            STRING
        OPTIONS(description = 'Package type or ecosystem (debian, alpine, npm, pip, etc.)'),

    data_source         STRING
        OPTIONS(description = 'Vulnerability database source (NVD, GHSA, Red Hat, etc.)')
)
PARTITION BY DATE(scan_timestamp)
CLUSTER BY severity, image, resource_namespace
OPTIONS(
    description = 'Parsed vulnerability records extracted from Trivy scan reports. Partitioned by day on scan_timestamp, clustered by severity, image, and namespace.',
    labels = [('team', 'devsecops'), ('data_classification', 'internal')],
    require_partition_filter = TRUE
);


-- -----------------------------------------------------------------------------
-- View: latest_vulnerabilities
-- -----------------------------------------------------------------------------
-- Provides the most recent scan result for each unique combination of
-- vulnerability, package, and image. Useful for dashboards showing the
-- current vulnerability posture without duplicates from repeated scans.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW `${PROJECT_ID}.${DATASET}.latest_vulnerabilities` AS
WITH ranked AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY vulnerability_id, package_name, image
            ORDER BY scan_timestamp DESC
        ) AS rn
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
)
SELECT
    * EXCEPT(rn)
FROM ranked
WHERE rn = 1;


-- -----------------------------------------------------------------------------
-- View: vulnerability_summary
-- -----------------------------------------------------------------------------
-- Aggregated summary of vulnerability counts by severity, namespace, and
-- image. Designed for executive dashboards and compliance reporting.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW `${PROJECT_ID}.${DATASET}.vulnerability_summary` AS
SELECT
    resource_namespace,
    resource_name,
    image,
    COUNTIF(severity = 'CRITICAL')  AS critical_count,
    COUNTIF(severity = 'HIGH')      AS high_count,
    COUNTIF(severity = 'MEDIUM')    AS medium_count,
    COUNTIF(severity = 'LOW')       AS low_count,
    COUNTIF(severity = 'UNKNOWN')   AS unknown_count,
    COUNT(*)                        AS total_count,
    COUNTIF(fixed_version IS NOT NULL AND fixed_version != '') AS fixable_count,
    MAX(scan_timestamp)             AS latest_scan,
    MAX(cvss_score)                 AS max_cvss_score
FROM `${PROJECT_ID}.${DATASET}.latest_vulnerabilities`
GROUP BY resource_namespace, resource_name, image;
