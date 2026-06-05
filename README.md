# 🛡️ Automated Security Log Parser & Threat Analytics

A lightweight, high-performance log parsing and security analytics engine designed to identify web application threats and automate security telemetry logging.

## 🛠️ Technology Stack
* **Python 3.x** (Advanced Data Processing & RegEx Normalization)
* **SQL / SQLite** (Relational Storage & Incident Analytics)

## 🚀 Key Features
* **Custom RegEx Log Ingestion:** Parses standard web server access logs with high resilience against whitespace and format anomalies.
* **Threat Intelligence Heuristics:** Automatically detects **SQL Injection (SQLi)** patterns and directory enumeration.
* **Stateful Session Tracking:** Tracks consecutive authentication failures to dynamically elevate incidents to **High Severity Brute Force Attacks**.
* **Database Whitelisting:** Integrates relational database lookups to filter out authorized internal IP addresses, eliminating False Positives.

## 📊 Analytics Queries Inside
The project repository includes structured `database.sql` templates for security reporting, such as tracking top threat actors and grouping incident severity.

---
## 👤 Author & Maintainer

* **Name:** Remikhanov Shamil
* **Role:** Cybersecurity & Data Analytics Specialist
* **Copyright:** © 2026 Remikhanov Shamil. All Rights Reserved.