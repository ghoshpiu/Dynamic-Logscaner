# ETL Log Monitoring and Auditing Framework

This project provides a robust framework for **automated log scanning, session metadata extraction, and audit trail maintenance** for ETL processes. It consists of two main components:

- `LogScanner.py`: Scans raw log files for relevant metadata and error patterns.
- `SessionAuditLoader.py`: Extracts structured session-level insights and loads them into Snowflake audit tables.

---

## 🔧 Project Structure

```
📁 log-audit-framework/
│
├── LogScanner.py               # Scans logs for keywords, stores in LOGSCAN_RESULTS table
├── SessionAuditLoader.py       # Parses and loads session-level metadata into ETL_LOG_AUDIT
├── scan_config.json            # Keyword/regex-based rules for log scanning
├── field_mappings.json         # Dynamic mappings for session field extraction
├── last_processed_timestamp.txt  # Tracks last scan timestamp for incremental runs
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 📌 Features

### LogScanner.py
- Scans INFA, CDGC, DBT, Mass Ingestion, CI/CD and other log files.
- Keyword and regex-driven matching using `scan_config.json`.
- Dynamically assigns `SYSTEM_TYPE` based on log content.
- Supports structured CSV and unstructured logs.
- Inserts results into `LOGSCAN_RESULTS` table in Snowflake.
- Tracks processed timestamps and avoids duplicates.

### SessionAuditLoader.py
- Reads grouped logs from `LOGSCAN_RESULTS` using `LOGSCAN_ID`.
- Dynamically extracts key fields using `field_mappings.json`.
- Parses INFA-specific row counts and detects session success/failure.
- Stores session details into `ETL_LOG_AUDIT` table.
- Populates `SOURCE_NAME` and `TARGET_NAME` as JSON arrays.
- Ensures no overwriting of existing data with blanks.

---

## ✅ Requirements

- Python 3.8+
- Snowflake Connector for Python
- Pandas, Regex, JSON

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

- **`scan_config.json`**: Define keyword/regex filters per log type.
- **`last_processed_timestamp.txt`**: Maintains max scan timestamp for incremental loading.
- **`last_scan_timestamp.json`**: Maintains last run timestamp for incremental loading.

---

## 🏃 How to Run

### Step 1: Scan Logs
```bash
python LogScanner.py
```
This will populate `LOGSCAN_RESULTS` table with matching lines from new or updated log files.

### Step 2: Load Session Metadata
```bash
python SessionAuditLoader.py
```
This will parse entries from `LOGSCAN_RESULTS`, validate completeness, and upsert into `ETL_LOG_AUDIT`.

---

## Use Cases

- End-to-end tracking of ETL jobs across tools like Informatica, DBT, or Mass Ingestion.
- Real-time monitoring and alerting for failed jobs.
- Power BI dashboards or automated reporting on ETL performance.


