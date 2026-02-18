-- =============================================================================
-- vuln_trends.sql
-- =============================================================================
-- Analyze vulnerability trends over time to identify improvements or
-- regressions in the security posture of the cluster.
--
-- This query aggregates daily vulnerability counts by severity, providing
-- time-series data suitable for dashboards and trend analysis. It also
-- calculates rolling 7-day averages and week-over-week change percentages.
--
-- Parameters:
--   Replace ${PROJECT_ID} and ${DATASET} with your actual values.
--   Adjust the INTERVAL to control the lookback window.
-- =============================================================================

-- Daily vulnerability counts by severity
WITH daily_counts AS (
    SELECT
        DATE(scan_timestamp) AS scan_date,
        COUNTIF(severity = 'CRITICAL')  AS critical_count,
        COUNTIF(severity = 'HIGH')      AS high_count,
        COUNTIF(severity = 'MEDIUM')    AS medium_count,
        COUNTIF(severity = 'LOW')       AS low_count,
        COUNTIF(severity = 'UNKNOWN')   AS unknown_count,
        COUNT(*)                        AS total_count,
        COUNTIF(fixed_version IS NOT NULL AND fixed_version != '') AS fixable_count,
        COUNT(DISTINCT image)           AS distinct_images_scanned,
        COUNT(DISTINCT vulnerability_id) AS distinct_cves
    FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
    WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
    GROUP BY scan_date
),

-- Add rolling averages
with_rolling AS (
    SELECT
        *,
        ROUND(AVG(critical_count) OVER (
            ORDER BY scan_date
            ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
        ), 1) AS critical_7d_avg,
        ROUND(AVG(high_count) OVER (
            ORDER BY scan_date
            ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
        ), 1) AS high_7d_avg,
        ROUND(AVG(total_count) OVER (
            ORDER BY scan_date
            ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
        ), 1) AS total_7d_avg
    FROM daily_counts
)

SELECT
    scan_date,
    critical_count,
    high_count,
    medium_count,
    low_count,
    unknown_count,
    total_count,
    fixable_count,
    distinct_images_scanned,
    distinct_cves,
    critical_7d_avg,
    high_7d_avg,
    total_7d_avg,
    -- Week-over-week change for critical+high
    ROUND(
        SAFE_DIVIDE(
            (critical_count + high_count) - LAG(critical_count + high_count, 7) OVER (ORDER BY scan_date),
            LAG(critical_count + high_count, 7) OVER (ORDER BY scan_date)
        ) * 100, 1
    ) AS critical_high_wow_pct_change
FROM with_rolling
ORDER BY scan_date DESC;


-- =============================================================================
-- Weekly summary variant (for executive reporting)
-- =============================================================================
-- Uncomment the query below for a weekly rollup instead of daily granularity.
-- =============================================================================

/*
SELECT
    DATE_TRUNC(DATE(scan_timestamp), WEEK(MONDAY)) AS week_start,
    COUNTIF(severity = 'CRITICAL')  AS critical_count,
    COUNTIF(severity = 'HIGH')      AS high_count,
    COUNTIF(severity = 'MEDIUM')    AS medium_count,
    COUNTIF(severity = 'LOW')       AS low_count,
    COUNT(*)                        AS total_count,
    COUNTIF(fixed_version IS NOT NULL AND fixed_version != '') AS fixable_count,
    COUNT(DISTINCT image)           AS distinct_images,
    COUNT(DISTINCT vulnerability_id) AS distinct_cves,
    COUNT(DISTINCT CONCAT(resource_namespace, '/', resource_name)) AS distinct_workloads
FROM `${PROJECT_ID}.${DATASET}.vulnerabilities`
WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 180 DAY)
GROUP BY week_start
ORDER BY week_start DESC;
*/
