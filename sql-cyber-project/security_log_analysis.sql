-- ============================================================
-- SQL Security Log Analysis Project
-- Author: [Your Name]
-- Created: June 2026
-- Description: Simulated security log analysis project
-- demonstrating how SQL can be used for cyber defense
-- analysis, threat detection, and SOC reporting.
-- Built as part of preparation for the DoW Cyber Registered
-- Apprenticeship Program (Cyber RAP)
-- ============================================================

USE CyberSecurityLogs;

-- ============================================================
-- DATABASE SETUP
-- ============================================================

-- Create Security Log Table
CREATE TABLE SecurityLogs (
    event_id INT IDENTITY(1,1) PRIMARY KEY,
    event_timestamp DATETIME,
    user_id VARCHAR(50),
    ip_address VARCHAR(20),
    event_type VARCHAR(50),
    severity VARCHAR(10),
    status VARCHAR(10),
    description VARCHAR(255)
);

-- ============================================================
-- SAMPLE DATA
-- Simulated security events across a 4 day period (June 1-4)
-- Includes: brute force, after hours logins, unauthorized
-- file access, port scanning, SQL injection, and malware
-- ============================================================

INSERT INTO SecurityLogs (event_timestamp, user_id, ip_address, event_type, severity, status, description)
VALUES
-- Failed login attempts (potential brute force)
('2026-06-01 08:15:00', 'jsmith', '192.168.1.105', 'Failed Login', 'Medium', 'Blocked', 'Invalid password attempt'),
('2026-06-01 08:16:00', 'jsmith', '192.168.1.105', 'Failed Login', 'Medium', 'Blocked', 'Invalid password attempt'),
('2026-06-01 08:17:00', 'jsmith', '192.168.1.105', 'Failed Login', 'Medium', 'Blocked', 'Invalid password attempt'),
('2026-06-01 08:18:00', 'jsmith', '192.168.1.105', 'Failed Login', 'Medium', 'Blocked', 'Invalid password attempt'),
('2026-06-01 08:19:00', 'jsmith', '192.168.1.105', 'Failed Login', 'Medium', 'Blocked', 'Invalid password attempt'),
('2026-06-01 08:20:00', 'jsmith', '192.168.1.105', 'Failed Login', 'High', 'Blocked', 'Account locked after multiple failures'),

-- Successful logins
('2026-06-01 09:00:00', 'mjohnson', '10.0.0.45', 'Successful Login', 'Low', 'Allowed', 'Normal user login'),
('2026-06-01 09:05:00', 'agarcia', '10.0.0.78', 'Successful Login', 'Low', 'Allowed', 'Normal user login'),
('2026-06-01 11:30:00', 'bwilliams', '10.0.0.92', 'Successful Login', 'Low', 'Allowed', 'Normal user login'),

-- After hours logins (suspicious)
('2026-06-02 02:15:00', 'agarcia', '10.0.0.78', 'Successful Login', 'High', 'Flagged', 'Login outside business hours'),
('2026-06-02 03:45:00', 'mjohnson', '185.220.101.45', 'Successful Login', 'High', 'Flagged', 'Login from unknown external IP'),

-- File access events
('2026-06-02 10:00:00', 'bwilliams', '10.0.0.92', 'File Access', 'Low', 'Allowed', 'Accessed quarterly report'),
('2026-06-02 10:15:00', 'bwilliams', '10.0.0.92', 'File Access', 'Medium', 'Flagged', 'Accessed restricted HR files'),
('2026-06-02 10:16:00', 'bwilliams', '10.0.0.92', 'File Access', 'Medium', 'Flagged', 'Accessed restricted payroll files'),

-- Port scanning (reconnaissance)
('2026-06-03 14:00:00', 'unknown', '203.0.113.99', 'Port Scan', 'High', 'Blocked', 'Multiple port scan detected'),
('2026-06-03 14:01:00', 'unknown', '203.0.113.99', 'Port Scan', 'High', 'Blocked', 'Continued port scan activity'),
('2026-06-03 14:02:00', 'unknown', '203.0.113.99', 'Port Scan', 'High', 'Blocked', 'Continued port scan activity'),

-- SQL Injection attempts
('2026-06-03 15:30:00', 'unknown', '198.51.100.22', 'SQLi Attempt', 'High', 'Blocked', 'Suspicious input detected: OR 1=1'),
('2026-06-03 15:31:00', 'unknown', '198.51.100.22', 'SQLi Attempt', 'High', 'Blocked', 'Suspicious input detected: DROP TABLE'),
('2026-06-03 15:32:00', 'unknown', '198.51.100.22', 'SQLi Attempt','High', 'Blocked', 'Suspicious input detected: UNION SELECT'),

-- Malware detection
('2026-06-04 09:00:00', 'trodriguez', '10.0.0.55', 'Malware Detected', 'High', 'Blocked', 'Trojan detected in email attachment'),
('2026-06-04 09:30:00', 'trodriguez', '10.0.0.55', 'Malware Detected', 'High', 'Blocked', 'Ransomware signature detected'),

-- Normal activity
('2026-06-04 10:00:00', 'mjohnson', '10.0.0.45', 'File Access', 'Low', 'Allowed', 'Accessed project documentation'),
('2026-06-04 11:00:00', 'agarcia', '10.0.0.78', 'Successful Login', 'Low', 'Allowed', 'Normal user login'),
('2026-06-04 13:00:00', 'bwilliams', '10.0.0.92', 'File Access', 'Low', 'Allowed', 'Accessed marketing materials');

-- ============================================================
-- SECURITY ANALYSIS QUERIES
-- ============================================================

-- ------------------------------------------------------------
-- Query 1: Brute Force Detection
-- Identifies users with 3 or more failed login attempts
-- High volume of failed logins may indicate a brute force attack
-- ------------------------------------------------------------

SELECT
    user_id,
    ip_address,
    COUNT(*) AS failed_attempts,
    MIN(event_timestamp) AS first_attempt,
    MAX(event_timestamp) AS last_attempt
FROM SecurityLogs
WHERE event_type = 'Failed Login'
GROUP BY user_id, ip_address
HAVING COUNT(*) >= 3
ORDER BY failed_attempts DESC;

-- ------------------------------------------------------------
-- Query 2: Threat Identification by IP Address
-- Identifies external IP addresses triggering high severity events
-- Used to build a threat watchlist for firewall blocking
-- ------------------------------------------------------------

SELECT
    ip_address,
    COUNT(*) AS total_events,
    COUNT(CASE WHEN severity = 'High' THEN 1 END) AS high_severity_count,
    COUNT(CASE WHEN status = 'Blocked' THEN 1 END) AS blocked_count,
    MIN(event_timestamp) AS first_seen,
    MAX(event_timestamp) AS last_seen
FROM SecurityLogs
WHERE severity = 'High'
AND ip_address NOT LIKE '10.%'
AND ip_address NOT LIKE '192.168.%'
GROUP BY ip_address
ORDER BY high_severity_count DESC;

-- ------------------------------------------------------------
-- Query 3: After Hours Login Detection
-- Identifies successful logins outside business hours (9am - 5pm)
-- After hours logins may indicate compromised accounts or insider threats
-- ------------------------------------------------------------

SELECT
    user_id,
    ip_address,
    event_timestamp,
    event_type,
    status,
    description,
    DATENAME(WEEKDAY, event_timestamp) AS day_of_week,
    DATEPART(HOUR, event_timestamp) AS hour_of_login
FROM SecurityLogs
WHERE event_type = 'Successful Login'
AND (DATEPART(HOUR, event_timestamp) < 9
OR DATEPART(HOUR, event_timestamp) >= 17)
ORDER BY event_timestamp;

-- ------------------------------------------------------------
-- Query 4: Insider Threat Detection
-- Identifies users accessing restricted files they shouldn't have
-- Repeated restricted file access may indicate data theft or privilege abuse
-- ------------------------------------------------------------

SELECT
    user_id,
    ip_address,
    event_timestamp,
    event_type,
    status,
    description,
    COUNT(*) OVER (PARTITION BY user_id) AS total_restricted_access
FROM SecurityLogs
WHERE event_type = 'File Access'
AND status = 'Flagged'
ORDER BY user_id, event_timestamp;

-- ------------------------------------------------------------
-- Query 5: SQL Injection Attack Detection
-- Identifies SQL injection attempts against the organization
-- Repeated SQLi attempts from same IP indicate an active attack
-- ------------------------------------------------------------

SELECT
    ip_address,
    user_id,
    event_timestamp,
    event_type,
    status,
    description,
    COUNT(*) OVER (PARTITION BY ip_address) AS total_sqli_attempts
FROM SecurityLogs
WHERE event_type = 'SQLi Attempt'
ORDER BY event_timestamp;

-- ------------------------------------------------------------
-- Query 6: Persistent Threat Tracking
-- Identifies IP addresses that were blocked multiple times
-- Repeated blocks indicate persistent threats requiring permanent blacklisting
-- ------------------------------------------------------------

SELECT
    ip_address,
    COUNT(*) AS total_blocked_events,
    MIN(event_timestamp) AS first_blocked,
    MAX(event_timestamp) AS last_blocked,
    DATEDIFF(MINUTE, MIN(event_timestamp), MAX(event_timestamp)) AS minutes_active,
    STRING_AGG(event_type, ', ') AS attack_types
FROM SecurityLogs
WHERE status = 'Blocked'
GROUP BY ip_address
HAVING COUNT(*) > 1
ORDER BY total_blocked_events DESC;

-- ------------------------------------------------------------
-- Query 7: Event Count by Severity
-- Generates a summary report of events by severity level
-- Used for SOC shift reporting and management briefings
-- ------------------------------------------------------------

SELECT
    severity,
    COUNT(*) AS total_events,
    COUNT(CASE WHEN status = 'Blocked' THEN 1 END) AS blocked,
    COUNT(CASE WHEN status = 'Flagged' THEN 1 END) AS flagged,
    COUNT(CASE WHEN status = 'Allowed' THEN 1 END) AS allowed,
    CAST(ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1) AS DECIMAL(5,1)) AS percentage_of_total
FROM SecurityLogs
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'High' THEN 1
        WHEN 'Medium' THEN 2
        WHEN 'Low' THEN 3
    END;

-- ------------------------------------------------------------
-- Query 8: Full Suspicious Activity Report
-- Consolidates all suspicious events into one executive summary
-- Used for end of shift briefings and management reporting
-- ------------------------------------------------------------

SELECT
    event_timestamp,
    user_id,
    ip_address,
    event_type,
    severity,
    status,
    description,
    CASE
        WHEN event_type = 'Failed Login' AND
            (SELECT COUNT(*) FROM SecurityLogs s2
             WHERE s2.user_id = s1.user_id
             AND s2.event_type = 'Failed Login') >= 3
            THEN 'Brute Force Suspected'
        WHEN event_type = 'SQLi Attempt'
            THEN 'SQL Injection Attack'
        WHEN event_type = 'Port Scan'
            THEN 'Network Reconnaissance'
        WHEN event_type = 'Malware Detected'
            THEN 'Active Malware Infection'
        WHEN event_type = 'File Access' AND status = 'Flagged'
            THEN 'Insider Threat Suspected'
        WHEN event_type = 'Successful Login' AND status = 'Flagged'
            THEN 'Anomalous Login'
        ELSE 'Monitor'
    END AS threat_classification,
    CASE
        WHEN severity = 'High' AND status = 'Flagged'
            THEN 'IMMEDIATE ACTION REQUIRED'
        WHEN severity = 'High' AND status = 'Blocked'
            THEN 'Blocked - Monitor for Recurrence'
        WHEN severity = 'Medium' AND status = 'Flagged'
            THEN 'Escalate to Senior Analyst'
        ELSE 'Log and Monitor'
    END AS recommended_action
FROM SecurityLogs s1
WHERE status != 'Allowed'
ORDER BY
    CASE severity
        WHEN 'High' THEN 1
        WHEN 'Medium' THEN 2
        WHEN 'Low' THEN 3
    END,
    event_timestamp;
