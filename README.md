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

| # | Query | Security Focus |
|---|---|---|
| 1 | [Brute Force Detection](#query-1--brute-force-detection) | Attack Detection |
| 2 | [Threat Identification by IP](#query-2--threat-identification-by-ip-address) | Threat Intelligence |
| 3 | [After Hours Login Detection](#query-3--after-hours-login-detection) | Anomaly Detection |
| 4 | [Insider Threat Detection](#query-4--insider-threat-detection) | Insider Threat |
| 5 | [SQL Injection Detection](#query-5--sql-injection-attack-detection) | Attack Detection |
| 6 | [Persistent Threat Tracking](#query-6--persistent-threat-tracking) | Threat Intelligence |
| 7 | [Event Count by Severity](#query-7--event-count-by-severity) | SOC Reporting |
| 8 | [Full Suspicious Activity Report](#query-8--full-suspicious-activity-report) | Executive Summary |

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
