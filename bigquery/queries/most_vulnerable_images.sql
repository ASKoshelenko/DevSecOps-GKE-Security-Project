-- =============================================================================
-- most_vulnerable_images.sql
-- =============================================================================
-- Identify the container images with the highest number of vulnerabilities.
--
-- This query ranks images by their total vulnerability count, with a
-- breakdown by severity level. It uses only the latest scan results to
-- avoid counting duplicates from repeated scans. Useful for prioritizing
-- image remediation efforts and identifying base images that contribute
-- the most risk.
--
-- Parameters:
--   Replace ${PROJECT_ID} and ${DATASET} with your actual values.
-- =============================================================================

WITH latest_per_image AS (
    -- Deduplicate: keep only the most recent scan per vulnerability/image
    SELECT
        vulnerability_id,
        package_name,
        installed_version,
        fixed_version,
        severity,
        cvss_score,
        image,
        resource_namespace,
        resource_name,
        resource_kind,
        scan_timestamp,
        ROW_NUMBER() OVER (
            PARTITION BY vulnerability_id, package_name, image
            ORDER BY scan_timestamp DESC
        ) AS rn
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
),

deduplicated AS (
    SELECT * FROM latest_per_image WHERE rn = 1
),

image_summary AS (
    SELECT
        image,
        COUNT(*)                                    AS total_vulns,
        COUNTIF(severity = 'CRITICAL')              AS critical_count,
        COUNTIF(severity = 'HIGH')                  AS high_count,
        COUNTIF(severity = 'MEDIUM')                AS medium_count,
        COUNTIF(severity = 'LOW')                   AS low_count,
        COUNTIF(severity = 'UNKNOWN')               AS unknown_count,
        COUNTIF(fixed_version IS NOT NULL
                AND fixed_version != '')             AS fixable_count,
        MAX(cvss_score)                             AS max_cvss_score,
        ROUND(AVG(cvss_score), 2)                   AS avg_cvss_score,
        COUNT(DISTINCT vulnerability_id)            AS distinct_cves,
        MAX(scan_timestamp)                         AS latest_scan,
        -- Collect distinct namespaces where this image is deployed
        ARRAY_AGG(DISTINCT resource_namespace IGNORE NULLS) AS deployed_namespaces
    FROM deduplicated
    GROUP BY image
)

SELECT
    image,
    total_vulns,
    critical_count,
    high_count,
    medium_count,
    low_count,
    unknown_count,
    fixable_count,
    ROUND(SAFE_DIVIDE(fixable_count, total_vulns) * 100, 1) AS fixable_pct,
    max_cvss_score,
    avg_cvss_score,
    distinct_cves,
    latest_scan,
    ARRAY_LENGTH(deployed_namespaces) AS deployed_in_namespace_count,
    deployed_namespaces,
    -- Risk score: weighted combination of severity counts
    (critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 1) AS risk_score
FROM image_summary
ORDER BY risk_score DESC, total_vulns DESC
LIMIT 50;
