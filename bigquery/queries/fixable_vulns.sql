-- =============================================================================
-- fixable_vulns.sql
-- =============================================================================
-- Identify vulnerabilities that have known fixes available.
--
-- This query finds all vulnerabilities where a fixed_version exists,
-- representing "low-hanging fruit" that can be resolved by upgrading
-- the affected packages. Results are grouped by image and package to
-- provide actionable remediation guidance.
--
-- Parameters:
--   Replace ${PROJECT_ID} and ${DATASET} with your actual values.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Part 1: Detailed list of fixable vulnerabilities (most impactful first)
-- ---------------------------------------------------------------------------
WITH latest_fixable AS (
    SELECT
        vulnerability_id,
        package_name,
        installed_version,
        fixed_version,
        severity,
        cvss_score,
        title,
        image,
        resource_namespace,
        resource_name,
        resource_kind,
        scan_timestamp,
        primary_link,
        pkg_type,
        ROW_NUMBER() OVER (
            PARTITION BY vulnerability_id, package_name, image
            ORDER BY scan_timestamp DESC
        ) AS rn
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE
        scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        AND fixed_version IS NOT NULL
        AND fixed_version != ''
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
    pkg_type
FROM latest_fixable
WHERE rn = 1
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        WHEN 'LOW'      THEN 4
        ELSE 5
    END ASC,
    cvss_score DESC NULLS LAST;


-- ---------------------------------------------------------------------------
-- Part 2: Package upgrade summary
-- ---------------------------------------------------------------------------
-- Aggregates fixable vulnerabilities by package and image, showing how many
-- CVEs would be resolved by upgrading each package. This provides a
-- prioritized remediation plan: upgrade the packages that eliminate the
-- most vulnerabilities first.
-- ---------------------------------------------------------------------------

/*
WITH latest_fixable AS (
    SELECT
        vulnerability_id,
        package_name,
        installed_version,
        fixed_version,
        severity,
        cvss_score,
        image,
        resource_namespace,
        ROW_NUMBER() OVER (
            PARTITION BY vulnerability_id, package_name, image
            ORDER BY scan_timestamp DESC
        ) AS rn
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE
        scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        AND fixed_version IS NOT NULL
        AND fixed_version != ''
),

deduplicated AS (
    SELECT * FROM latest_fixable WHERE rn = 1
)

SELECT
    image,
    package_name,
    installed_version,
    -- The target version to upgrade to (pick the highest fixed_version seen)
    MAX(fixed_version) AS recommended_version,
    COUNT(*) AS vulns_fixed_by_upgrade,
    COUNTIF(severity = 'CRITICAL') AS critical_fixed,
    COUNTIF(severity = 'HIGH') AS high_fixed,
    COUNTIF(severity = 'MEDIUM') AS medium_fixed,
    MAX(cvss_score) AS max_cvss_score,
    ARRAY_AGG(DISTINCT vulnerability_id ORDER BY vulnerability_id) AS cve_list,
    ARRAY_AGG(DISTINCT resource_namespace IGNORE NULLS) AS affected_namespaces
FROM deduplicated
GROUP BY image, package_name, installed_version
ORDER BY
    vulns_fixed_by_upgrade DESC,
    max_cvss_score DESC NULLS LAST;
*/


-- ---------------------------------------------------------------------------
-- Part 3: Fixable vs. unfixable summary by namespace
-- ---------------------------------------------------------------------------
-- Provides a namespace-level overview of the fixable vulnerability ratio,
-- helping teams understand what percentage of their risk is actionable.
-- ---------------------------------------------------------------------------

/*
WITH latest AS (
    SELECT
        vulnerability_id,
        package_name,
        fixed_version,
        severity,
        image,
        resource_namespace,
        ROW_NUMBER() OVER (
            PARTITION BY vulnerability_id, package_name, image
            ORDER BY scan_timestamp DESC
        ) AS rn
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
),

deduplicated AS (
    SELECT * FROM latest WHERE rn = 1
)

SELECT
    COALESCE(resource_namespace, 'UNKNOWN') AS namespace,
    COUNT(*) AS total_vulns,
    COUNTIF(fixed_version IS NOT NULL AND fixed_version != '') AS fixable_count,
    COUNTIF(fixed_version IS NULL OR fixed_version = '') AS unfixable_count,
    ROUND(
        SAFE_DIVIDE(
            COUNTIF(fixed_version IS NOT NULL AND fixed_version != ''),
            COUNT(*)
        ) * 100, 1
    ) AS fixable_pct,
    COUNTIF(severity IN ('CRITICAL', 'HIGH')
            AND fixed_version IS NOT NULL
            AND fixed_version != '') AS fixable_critical_high,
    COUNT(DISTINCT image) AS distinct_images
FROM deduplicated
GROUP BY namespace
ORDER BY fixable_critical_high DESC, total_vulns DESC;
*/
