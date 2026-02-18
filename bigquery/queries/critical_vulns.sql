-- =============================================================================
-- critical_vulns.sql
-- =============================================================================
-- Find all CRITICAL and HIGH severity vulnerabilities from the latest scans.
--
-- This query surfaces the most urgent vulnerabilities that require immediate
-- attention, sorted by CVSS score (highest risk first). It deduplicates
-- results to show only the most recent scan per vulnerability/image pair.
--
-- Parameters:
--   Replace ${PROJECT_ID} and ${DATASET} with your actual values.
--   Adjust the INTERVAL to control the lookback window.
-- =============================================================================

WITH latest_scans AS (
    SELECT
        vulnerability_id,
        package_name,
        installed_version,
        fixed_version,
        severity,
        cvss_score,
        title,
        description,
        resource_namespace,
        resource_name,
        resource_kind,
        image,
        scan_timestamp,
        primary_link,
        target,
        pkg_type,
        ROW_NUMBER() OVER (
            PARTITION BY vulnerability_id, package_name, image
            ORDER BY scan_timestamp DESC
        ) AS row_num
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE
        scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        AND severity IN ('CRITICAL', 'HIGH')
)

SELECT
    vulnerability_id,
    severity,
    cvss_score,
    package_name,
    installed_version,
    fixed_version,
    title,
    image,
    resource_namespace,
    resource_name,
    resource_kind,
    scan_timestamp,
    primary_link,
    target,
    pkg_type,
    CASE
        WHEN fixed_version IS NOT NULL AND fixed_version != '' THEN 'FIXABLE'
        ELSE 'NO FIX AVAILABLE'
    END AS fix_status
FROM latest_scans
WHERE row_num = 1
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
    END ASC,
    cvss_score DESC NULLS LAST,
    vulnerability_id ASC;
