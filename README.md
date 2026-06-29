# SQL Security Log Analysis Project

## Overview
This project demonstrates how Structured Query Language (SQL) can be applied 
to cybersecurity defense — specifically to the kind of log analysis and threat 
detection work performed daily by a Cyber Defense Analyst in a Security 
Operations Center (SOC).

---

## Motivation
As someone with a strong SQL background, I wanted to bridge my existing skills 
into cybersecurity. This project was an opportunity to explore how the same 
analytical thinking used in data analysis applies directly to cyber defense — 
specifically how security analysts use SQL to detect threats, investigate 
anomalies, and communicate findings clearly to stakeholders.

What I didn't expect when I started exploring cybersecurity was how much of it 
comes down to asking the right questions about data. SOC analysts spend a 
significant part of their day querying logs — looking for patterns, anomalies, 
and threats hiding in plain sight. The skill set was already there. I just 
needed to point it in a new direction. This project is my attempt to explore 
that intersection.

---

## About This Project
This project was developed with the guidance of Claude (Anthropic's AI 
assistant) as a learning tool. All queries were built incrementally — each one 
explained, understood, and verified before moving to the next. The goal was not 
to generate code blindly, but to understand how SQL applies to real security 
scenarios and be able to explain every line.

I come from a UX/UI design background with strong SQL skills. This project 
bridges those foundations into cybersecurity — showing how analytical thinking, 
data querying, and systems understanding apply directly to cyber defense roles. 
Some of the more complex queries were developed with guidance, but I understand 
every line of code and can explain exactly what it does and why it matters from 
a security perspective.

---

## Database
- **Tool:** Microsoft SQL Server (SSMS) 22
- **Database:** CyberSecurityLogs
- **Table:** SecurityLogs
- **Records:** 25 simulated security events across 4 days (June 1–4, 2026)

### Dataset Fields
| Column | Type | Description |
|---|---|---|
| event_id | INT | Unique auto-generated event identifier |
| event_timestamp | DATETIME | Date and time the event occurred |
| user_id | VARCHAR | Username associated with the event |
| ip_address | VARCHAR | IP address the event originated from |
| event_type | VARCHAR | Type of security event |
| severity | VARCHAR | Event severity — Low, Medium, or High |
| status | VARCHAR | System response — Allowed, Blocked, or Flagged |
| description | VARCHAR | Plain English description of the event |

### Simulated Threat Scenarios
The dataset includes the following real-world security scenarios:
- Brute force login attack targeting a user account
- After hours logins from internal and external IPs
- Unauthorized access to restricted HR and payroll files
- External port scanning (network reconnaissance)
- SQL injection attempts using common attack strings
- Active malware infection (trojan and ransomware)
- Normal baseline activity for comparison

---

## Queries

### Query 1 — Brute Force Detection
Identifies users with 3 or more failed login attempts in a session.
High volume of failed logins may indicate a brute force attack targeting
a user account.

**Security relevance:** Brute force attacks are one of the most common 
attack vectors. Early detection prevents account compromise.

---

### Query 2 — Threat Identification by IP Address
Identifies external IP addresses triggering high severity events.
Filters out internal IP ranges to focus on external threats only.

**Security relevance:** Building a threat watchlist of malicious IPs 
allows analysts to recommend firewall blocks before further damage occurs.

---

### Query 3 — After Hours Login Detection
Identifies successful logins outside business hours (9am–5pm).
Uses DATEPART to extract the hour from each timestamp for filtering.

**Security relevance:** After hours logins may indicate compromised 
accounts being used by attackers or insider threats operating covertly.

---

### Query 4 — Insider Threat Detection
Identifies users accessing restricted files they are not authorized to view.
Uses a window function to count total restricted accesses per user.

**Security relevance:** Insider threats are among the most damaging 
security incidents. Repeated restricted file access may indicate data 
theft or privilege abuse requiring HR escalation.

---

### Query 5 — SQL Injection Attack Detection
Identifies SQL injection attempts in the security logs.
Flags common SQLi strings including OR 1=1, DROP TABLE, and UNION SELECT.

**Security relevance:** SQL injection is one of the most common and 
dangerous web attack types. Because of my SQL background I understand 
exactly what each injection string is attempting to accomplish — making 
severity assessment faster and more accurate.

---

### Query 6 — Persistent Threat Tracking
Identifies IP addresses blocked more than once across the log period.
Uses STRING_AGG to summarize all attack types per IP in one row.

**Security relevance:** Persistent threats show intent — an attacker 
who keeps coming back despite being blocked requires permanent blacklisting 
at the firewall level, not just individual event responses.

---

### Query 7 — Event Count by Severity
Generates a summary report of all events grouped by severity level.
Includes blocked, flagged, and allowed counts plus percentage of total.

**Security relevance:** SOC analysts produce shift reports like this to 
brief incoming teams and justify security investments to management. 
Clean, quantified summaries communicate risk faster than raw log data.

---

### Query 8 — Full Suspicious Activity Report
Consolidates all suspicious events into one executive summary.
Adds two analyst generated columns — threat classification and 
recommended action — using CASE WHEN logic applied to event patterns.

**Security relevance:** This is the deliverable a Cyber Defense Analyst 
hands to their manager at the end of a shift. It translates raw log data 
into actionable intelligence — identifying what happened, how serious it 
is, and what needs to happen next.

---

## SQL Skills Demonstrated
- SELECT, FROM, WHERE, GROUP BY, HAVING, ORDER BY
- Aggregate functions — COUNT, MIN, MAX
- Window functions — COUNT OVER, PARTITION BY
- Conditional logic — CASE WHEN, ELSE
- Date functions — DATEPART, DATENAME, DATEDIFF
- String functions — STRING_AGG
- Correlated subqueries
- Custom sorting logic
- Filtering internal vs external IP ranges

---

## Repository Structure
```
sql-cyber-project/
├── security_log_analysis.sql
└── README.md
```
