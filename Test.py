# --- Imports ---
import re
import os
import json
from datetime import datetime
from collections import defaultdict
import snowflake.connector

    
# --- Regex-based error detection patterns ---
ERROR_PATTERNS = [
    r"\b(error|fatal|fail(ed|ure)?|exception|traceback|rollback|abort|terminated)\b",
    r"\bexit code\s*[:=]?\s*\d+\b",
    r"\btask .* failed\b",
    r"\bnullpointerexception\b",
    r"\bunhandled\b",
    r"\bconnection.*(refused|timed out)\b",
    r"\bsegmentation fault\b",
]

def is_error_line(line, patterns=ERROR_PATTERNS):
    line = line.strip().lower()

    # Skip known benign summary lines
    benign_patterns = [
        r"\bdone\..*?(pass|warn|error|skip|no-op|total)\s*=",
        r"\b(pass|success|ok)\s*\d*\b",
        r"\berror\s*=\s*0\b",
        r"\bcompleted successfully\b"
    ]

    for safe_pat in benign_patterns:
        if re.search(safe_pat, line):
            return False

    # Then apply actual error patterns
    return any(re.search(pat, line) for pat in patterns)





# --- Snowflake Connection ---
def setup_snowflake_connection():
    return snowflake.connector.connect(
        user='svc_python',
        password='Fb0Ie14bBdgsIducn1',
        account='CPTECHPARTNERORG-CPTECHPARTNER',
        warehouse='CTI_OTHER',
        database='CTI_AUDIT_FW',
        schema='CTI_AUDIT',
        role='CTI_AUDIT_ADMIN'
    )

# --- Fetch recent LOGSCAN_IDs ---
def fetch_recent_logscan_ids(cursor, last_timestamp, batch_size=100):
    last_ts_str = last_timestamp.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        SELECT ID
        FROM (
            SELECT ID, MAX(SCAN_TIMESTAMP) AS MAX_TS
            FROM CTI_AUDIT_FW.CTI_AUDIT.LOGSCAN_RESULTS
            WHERE SCAN_TIMESTAMP > %s
            GROUP BY ID
        )
        ORDER BY MAX_TS ASC
        LIMIT %s
    """, (last_ts_str, batch_size))
    return [row[0] for row in cursor.fetchall()]

# --- Fetch logs for a specific LOGSCAN_ID ---
def fetch_log_entries(cursor, logscan_id):
    cursor.execute("""
        SELECT ID, FILE_NAME, LINE_NUMBER, LINE_TIMESTAMP, MATCHING_LINE, SCAN_TIMESTAMP,SYSTEM_TYPE
        FROM CTI_AUDIT_FW.CTI_AUDIT.LOGSCAN_RESULTS
        WHERE ID = %s
        ORDER BY LINE_NUMBER, SCAN_TIMESTAMP
    """, (logscan_id,))
    return cursor.fetchall()

# --- Structure logs by session ---
def structure_logs_by_session(log_rows):
    session_logs = defaultdict(list)
    for row in log_rows:
        logscan_id, file_name, line_no, line_ts, matching_line, scan_ts,system_type = row
        session_logs[logscan_id].append({
            "FILE_NAME": file_name,
            "SYSTEM_TYPE": system_type,
            "LINE_NUMBER": line_no,
            "LINE_TIMESTAMP": line_ts,
            "MATCHING_LINE": matching_line,
            "SCAN_TIMESTAMP": scan_ts,
            "LOGSCAN_ID": logscan_id
        })
    for logscan_id in session_logs:
        session_logs[logscan_id].sort(key=lambda x: (x["LINE_NUMBER"], x["SCAN_TIMESTAMP"]))
    return session_logs

# --- Clean and standardize source/target names ---
def extract_base_names(name_set):
    cleaned = set()
    for name in name_set:
        name = name.strip(" .")
        upper_name = name.upper()
        base_name = upper_name.split("_OPT_")[0] if "_OPT_" in upper_name else upper_name
        cleaned.add(base_name.lower())
    return sorted(cleaned)  # <-- return list, not joined string


# --- Timestamp Extractor ---
def extract_timestamp(line, fallback_ts=None):
    formats = [
        (r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})", "%Y-%m-%d %H:%M:%S.%f"),
        (r"(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})", "%d-%b-%Y %H:%M:%S.%f"),
        (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z?)", "%Y-%m-%dT%H:%M:%S.%fZ"),
        (r"(\d{2}-[a-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})", "%d-%b-%Y %H:%M:%S.%f"),  # lowercase month
    ]
    for pattern, fmt in formats:
        match = re.search(pattern, line)
        if match:
            try:
                return datetime.strptime(match.group(1), fmt)
            except:
                continue
    return fallback_ts


# --- Parse a session's logs into structured fields ---
def parse_session_from_logs(logs, logscan_id):
    session = {
        "FILE_NAME": logs[0].get("FILE_NAME"),
        "SYSTEM_TYPE": logs[0].get("SYSTEM_TYPE"),
        "TASK_RUN_ID": None,
        "USERNAME": None,
        "TASK_NAME": None,
        "SESSION_START_TS": None,
        "SESSION_END_TS": None,
        "SOURCE_SUCCESS_ROWCNT": 0,
        "SOURCE_ERROR_ROWCNT": 0,
        "TARGET_SUCCESS_ROWCNT": 0,
        "TARGET_ERROR_ROWCNT": 0,
        "ERROR_MESSAGE": 'NA',
        "RUN_STATUS_CODE": 1,
        "RUN_STATUS": "Success",
        "LASTUPDATED": datetime.now(),
        "SOURCE_NAME": set(),
        "TARGET_NAME": set(),
        "WARNINGS": set(),
        "TOTAL_DURATION": None,
        "LOGSCAN_ID": logscan_id
    }

    timestamps = []
    source_stats, target_stats = {}, {}
    current_section, current_table = None, None
    has_failure, error_lines = False, set()

    # Markers for clean status detection
    success_markers = ["session run completed successfully", "session completed successfully", "session completed"]
    failure_markers = ["session run completed with failure", "session failed", "aborted", "terminated"]

    found_success = False
    found_failure = False

    for log in logs:
        line = str(log.get("MATCHING_LINE") or "").strip()
        lower = line.lower()

        # Always extract timestamps
        timestamp = log.get("LINE_TIMESTAMP") or extract_timestamp(line, log.get("SCAN_TIMESTAMP"))
        if timestamp:
            timestamps.append(timestamp)

        # --- Special handling for CDGC structured logs ---
        if session["SYSTEM_TYPE"] and session["SYSTEM_TYPE"].upper() in ["CDGC", "EXCEL", "CSV"]:
            try:
                log_json = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed lines

            # TASK_NAME
            if not session["TASK_NAME"]:
                session["TASK_NAME"] = log_json.get("serviceName")

            # USERNAME
            if not session["USERNAME"]:
                user_candidate = log_json.get("userId")
                if user_candidate and user_candidate.lower() != "null":
                    session["USERNAME"] = user_candidate

            # TIMESTAMP
            ts_str = log_json.get("timestamp")
            if ts_str:
                try:
                    timestamps.append(datetime.strptime(ts_str[:23], "%Y-%m-%dT%H:%M:%S.%f"))
                except ValueError:
                    pass

            # ERROR / FAIL detection
            level = log_json.get("level", "").upper()
            if "ERROR" in level or "EXCEPTION" in level or "FAIL" in level:
                has_failure = True
                error_lines.add(log_json.get("message", "Unknown error"))

            # WARNINGS
            if "WARN" in level:
                session["WARNINGS"].add(log_json.get("message", "warning"))

            continue




        # Detect session success/failure status cleanly
        if any(marker in lower for marker in success_markers):
            found_success = True
        if any(marker in lower for marker in failure_markers):
            found_failure = True

        # --- Informatica-specific Parsing (preserved exactly) ---
        if "source load summary" in lower:
            current_section = "SOURCE"
        elif "target load summary" in lower:
            current_section = "TARGET"

        if "table:" in lower:
            match = re.search(r"table:\s*\[(.*?)\]", line, re.IGNORECASE)
            if match:
                current_table = match.group(1).strip()

        if "output rows" in lower and current_table and current_section:
            row_values = re.findall(r"\[(\d+)]", line)
            if len(row_values) >= 4:
                output, affected, applied, rejected = map(int, row_values[:4])
                stats = {"output": output, "affected": affected, "applied": applied, "rejected": rejected}
                if current_section == "SOURCE":
                    source_stats[current_table] = stats
                    session["SOURCE_SUCCESS_ROWCNT"] += output
                    session["SOURCE_ERROR_ROWCNT"] += rejected
                elif current_section == "TARGET":
                    target_stats[current_table] = stats
                    session["TARGET_SUCCESS_ROWCNT"] += applied
                    session["TARGET_ERROR_ROWCNT"] += rejected

        # Capture warnings
        if "warning" in lower:
            # Remove ANSI escape codes (e.g., from DBT logs)
            cleaned_line = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", line)  # Remove color formatting

            # Normalize common warning patterns
            warning_patterns = [
                r"<warning>\s*:\s*(.*)",            # Informatica-style
                r"\[warning\]:\s*(.*)",             # DBT-style
                r"warning\s*[:\-]?\s*(.*)",         # General fallback
            ]

            for pattern in warning_patterns:
                match = re.search(pattern, cleaned_line, flags=re.IGNORECASE)
                if match:
                    session["WARNINGS"].add(match.group(1).strip())
                    break  # Only store one match per line


        # Detect error lines
        if is_error_line(line):
            has_failure = True
            cleaned_error = re.sub(r"^\[?\d{4}-\d{2}-\d{2}.*?]?\s*", "", line)
            cleaned_error = re.sub(r"^\s*\w+\s+\[[^]]+]\s+[^\s]+(?:\s+-)?", "", cleaned_error)
            error_lines.add(cleaned_error.strip())

        # --- Dynamic fallback parsing (for any log system) ---
        # Capture dynamic fields without hardcoding by checking general patterns
        if "run id" in lower and not session["TASK_RUN_ID"]:
            match = re.search(r"run id\s*:\s*(\d+)", lower)
            if match:
                session["TASK_RUN_ID"] = match.group(1).strip()

        if "task name" in lower and not session["TASK_NAME"]:
            match = re.search(r"task name\s*[:,]\s*(.*)", lower)
            if match:
                session["TASK_NAME"] = match.group(1).strip()

        if "starting ingestion job" in lower and not session["TASK_NAME"]:
            match = re.search(r"starting ingestion job\s*[:,]\s*(.*)", lower)
            if match:
                session["TASK_NAME"] = match.group(1).strip()

        if ("user:" in lower or "started by:" in lower) and not session["USERNAME"]:
            match = re.search(r"(user:|started by:)\s*(.*)", lower)
            if match:
                session["USERNAME"] = match.group(2).strip()

        if "importing source definition" in lower:
            match = re.search(r"importing source definition:\s*([^\s.]+)", lower)
            if match:
                session["SOURCE_NAME"].add(match.group(1).strip())

        if "importing target definition" in lower:
            match = re.search(r"importing target definition:\s*([^\s.]+)", lower)
            if match:
                session["TARGET_NAME"].add(match.group(1).strip())

        if "source:" in lower:
            match = re.search(r"source:\s*(.*)", lower)
            if match:
                session["SOURCE_NAME"].add(match.group(1).strip())

        if "target:" in lower:
            match = re.search(r"target:\s*(.*)", lower)
            if match:
                session["TARGET_NAME"].add(match.group(1).strip())

    # After looping through logs

    if timestamps:
        session["SESSION_START_TS"] = min(timestamps)
        session["SESSION_END_TS"] = max(timestamps)
        session["TOTAL_DURATION"] = str(session["SESSION_END_TS"] - session["SESSION_START_TS"]).split(".")[0]

    # Final Session Status Assignment
    if found_failure:
        session["RUN_STATUS_CODE"] = 0
        session["RUN_STATUS"] = "Failed"
    elif found_success:
        session["RUN_STATUS_CODE"] = 1
        session["RUN_STATUS"] = "Success"
    else:
        session["RUN_STATUS_CODE"] = 0 if has_failure else 1
        session["RUN_STATUS"] = "Failed" if has_failure else "Success"

    # Fill details
    session["ERROR_MESSAGE"] = json.dumps(sorted(error_lines)) if has_failure else "NA"
    session["SOURCE_ROW_DETAIL"] = json.dumps(source_stats)
    session["TARGET_ROW_DETAIL"] = json.dumps(target_stats)
    session["WARNINGS"] = json.dumps(sorted(session["WARNINGS"])) if session["WARNINGS"] else None


    # Cleanup and JSON format the sets
    source_cleaned = extract_base_names(session["SOURCE_NAME"])
    target_cleaned = extract_base_names(session["TARGET_NAME"])
    session["SOURCE_NAME"] = json.dumps(source_cleaned)
    session["TARGET_NAME"] = json.dumps(target_cleaned)

    # Nullify meaningless values
    for key in ["TASK_NAME", "USERNAME", "TASK_RUN_ID", "SOURCE_NAME", "TARGET_NAME"]:
        if session[key] == "" or session[key] == "NA":
            session[key] = None

    return session



# --- Upsert into session audit table ---
def upsert_session(cursor, session):
    cursor.execute("""
        MERGE INTO CTI_AUDIT_FW.CTI_AUDIT.ETL_LOG_AUDIT tgt
        USING (SELECT %(LOGSCAN_ID)s AS LOGSCAN_ID) AS src
        ON tgt.LOGSCAN_ID = src.LOGSCAN_ID
        WHEN MATCHED THEN UPDATE SET
            FILE_NAME = COALESCE(NULLIF(%(FILE_NAME)s, ''), tgt.FILE_NAME),
            SYSTEM_TYPE = COALESCE(NULLIF(%(SYSTEM_TYPE)s, ''), tgt.SYSTEM_TYPE),
            SOURCE_NAME = CASE 
                WHEN %(SOURCE_NAME)s IS NOT NULL AND %(SOURCE_NAME)s <> '[]' 
                THEN %(SOURCE_NAME)s 
                ELSE tgt.SOURCE_NAME 
            END,

            TARGET_NAME = CASE 
                WHEN %(TARGET_NAME)s IS NOT NULL AND %(TARGET_NAME)s <> '[]' 
                THEN %(TARGET_NAME)s 
                ELSE tgt.TARGET_NAME 
            END,
            TASK_RUN_ID = COALESCE(%(TASK_RUN_ID)s, tgt.TASK_RUN_ID),
            USERNAME = COALESCE(NULLIF(%(USERNAME)s, ''), tgt.USERNAME),
            TASK_NAME = COALESCE(NULLIF(%(TASK_NAME)s, ''), tgt.TASK_NAME),
            WARNINGS = COALESCE(%(WARNINGS)s, tgt.WARNINGS),
            SESSION_START_TS = COALESCE(%(SESSION_START_TS)s, tgt.SESSION_START_TS),
            SESSION_END_TS = COALESCE(%(SESSION_END_TS)s, tgt.SESSION_END_TS),
            TOTAL_DURATION = COALESCE(%(TOTAL_DURATION)s, tgt.TOTAL_DURATION),
            SOURCE_ROW_DETAIL = COALESCE(%(SOURCE_ROW_DETAIL)s, tgt.SOURCE_ROW_DETAIL),
            TARGET_ROW_DETAIL = COALESCE(%(TARGET_ROW_DETAIL)s, tgt.TARGET_ROW_DETAIL),
            SOURCE_SUCCESS_ROWCNT = COALESCE(%(SOURCE_SUCCESS_ROWCNT)s, tgt.SOURCE_SUCCESS_ROWCNT),
            SOURCE_ERROR_ROWCNT = COALESCE(%(SOURCE_ERROR_ROWCNT)s, tgt.SOURCE_ERROR_ROWCNT),
            TARGET_SUCCESS_ROWCNT = COALESCE(%(TARGET_SUCCESS_ROWCNT)s, tgt.TARGET_SUCCESS_ROWCNT),
            TARGET_ERROR_ROWCNT = COALESCE(%(TARGET_ERROR_ROWCNT)s, tgt.TARGET_ERROR_ROWCNT),
            ERROR_MESSAGE = CASE 
                WHEN %(ERROR_MESSAGE)s IS NOT NULL AND %(ERROR_MESSAGE)s <> 'NA' 
                THEN %(ERROR_MESSAGE)s 
                ELSE tgt.ERROR_MESSAGE 
            END,
            RUN_STATUS_CODE = %(RUN_STATUS_CODE)s,
            RUN_STATUS = %(RUN_STATUS)s,
            LASTUPDATED = %(LASTUPDATED)s
        WHEN NOT MATCHED THEN INSERT (
            LOGSCAN_ID,FILE_NAME, SYSTEM_TYPE, SOURCE_NAME, TARGET_NAME, TASK_RUN_ID,
            USERNAME, TASK_NAME, WARNINGS, SESSION_START_TS, SESSION_END_TS,
            TOTAL_DURATION, SOURCE_ROW_DETAIL, TARGET_ROW_DETAIL, SOURCE_SUCCESS_ROWCNT, SOURCE_ERROR_ROWCNT,
            TARGET_SUCCESS_ROWCNT, TARGET_ERROR_ROWCNT,
            ERROR_MESSAGE, RUN_STATUS_CODE, RUN_STATUS, LASTUPDATED
        ) VALUES (
            %(LOGSCAN_ID)s,%(FILE_NAME)s, %(SYSTEM_TYPE)s, %(SOURCE_NAME)s, %(TARGET_NAME)s, %(TASK_RUN_ID)s,
            %(USERNAME)s, %(TASK_NAME)s, %(WARNINGS)s, %(SESSION_START_TS)s, %(SESSION_END_TS)s,
            %(TOTAL_DURATION)s, %(SOURCE_ROW_DETAIL)s, %(TARGET_ROW_DETAIL)s, %(SOURCE_SUCCESS_ROWCNT)s, %(SOURCE_ERROR_ROWCNT)s,
            %(TARGET_SUCCESS_ROWCNT)s, %(TARGET_ERROR_ROWCNT)s,
            %(ERROR_MESSAGE)s, %(RUN_STATUS_CODE)s, %(RUN_STATUS)s, %(LASTUPDATED)s
        )
    """, session)



# --- View creation for completeness sorting ---
def create_completeness_view(cursor):
    print("[INFO] Creating or replacing completeness view with clean JSON casting...")

    cursor.execute("""
        CREATE OR REPLACE VIEW CTI_AUDIT_FW.CTI_AUDIT.VW_SESSION_AUDIT_COMPLETE_FIRST AS
        SELECT
            *,
            (
                CASE WHEN TASK_RUN_ID IS NULL THEN 1 ELSE 0 END +
                CASE WHEN USERNAME IS NULL THEN 1 ELSE 0 END +
                CASE WHEN TASK_NAME IS NULL THEN 1 ELSE 0 END +
                CASE WHEN SOURCE_ROW_DETAIL IS NULL OR SOURCE_ROW_DETAIL = '{}' THEN 1 ELSE 0 END +
                CASE WHEN TARGET_ROW_DETAIL IS NULL OR TARGET_ROW_DETAIL = '{}' THEN 1 ELSE 0 END +
                CASE WHEN SOURCE_NAME IS NULL OR TRY_PARSE_JSON(SOURCE_NAME) IS NULL THEN 1 ELSE 0 END +
                CASE WHEN TARGET_NAME IS NULL OR TRY_PARSE_JSON(TARGET_NAME) IS NULL THEN 1 ELSE 0 END +
                CASE WHEN SESSION_START_TS IS NULL THEN 1 ELSE 0 END +
                CASE WHEN SESSION_END_TS IS NULL THEN 1 ELSE 0 END +
                CASE WHEN WARNINGS IS NULL THEN 1 ELSE 0 END +
                CASE WHEN ERROR_MESSAGE IS NULL OR ERROR_MESSAGE = 'NA' THEN 1 ELSE 0 END
            ) AS NULL_COUNT
        FROM (
            SELECT
                LOGSCAN_ID,
                FILE_NAME,
                SYSTEM_TYPE,
                TRY_PARSE_JSON(SOURCE_NAME) AS SOURCE_NAME,
                TRY_PARSE_JSON(TARGET_NAME) AS TARGET_NAME,
                TASK_RUN_ID,
                USERNAME,
                TASK_NAME,
                TRY_PARSE_JSON(WARNINGS) AS WARNINGS,
                SESSION_START_TS,
                SESSION_END_TS,
                TOTAL_DURATION,
                TRY_PARSE_JSON(SOURCE_ROW_DETAIL) AS SOURCE_ROW_DETAIL,
                TRY_PARSE_JSON(TARGET_ROW_DETAIL) AS TARGET_ROW_DETAIL,
                SOURCE_SUCCESS_ROWCNT,
                SOURCE_ERROR_ROWCNT,
                TARGET_SUCCESS_ROWCNT,
                TARGET_ERROR_ROWCNT,
                TRY_PARSE_JSON(ERROR_MESSAGE) AS ERROR_MESSAGE,
                RUN_STATUS_CODE,
                RUN_STATUS,
                LASTUPDATED
            FROM CTI_AUDIT_FW.CTI_AUDIT.ETL_LOG_AUDIT
        ) t
        ORDER BY NULL_COUNT ASC, LOGSCAN_ID DESC;
    """)

    print("[INFO] View VW_SESSION_AUDIT_COMPLETE_FIRST created successfully with clean JSON formatting.")



# --- Main execution ---
def main():
    print("[INFO] Session Audit Loader started...")

    PARAM_FILE = "last_processed_timestamp.txt"

    def read_last_processed_ts():
        if os.path.exists(PARAM_FILE):
            with open(PARAM_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    return datetime.strptime(content, "%Y-%m-%d %H:%M:%S")
        # Fallback to epoch if file is empty or missing
        return datetime.strptime("1970-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")

    def write_last_processed_ts(ts):
        with open(PARAM_FILE, 'w') as f:
            f.write(ts.strftime("%Y-%m-%d %H:%M:%S"))

    # --- Read last processed timestamp automatically ---
    last_ts = read_last_processed_ts()
    print(f"[INFO] Using last processed timestamp: {last_ts}")


    # --- Connect to Snowflake ---
    conn = setup_snowflake_connection()
    cursor = conn.cursor()

    create_completeness_view(cursor)

    # --- Fetch logscan IDs ---
    recent_ids = fetch_recent_logscan_ids(cursor, last_ts, batch_size=100)

    cursor.execute("""
        SELECT LOGSCAN_ID
        FROM CTI_AUDIT_FW.CTI_AUDIT.VW_SESSION_AUDIT_COMPLETE_FIRST
        WHERE NULL_COUNT > 0
    """)
    incomplete_ids = [row[0] for row in cursor.fetchall()]

    logscan_ids = list(set(recent_ids + incomplete_ids))
    

    if not logscan_ids:
        print("[INFO] No new or incomplete LOGSCAN_IDs to process.")
        cursor.close()
        conn.close()
        return

    latest_processed_ts = last_ts

    for logscan_id in logscan_ids:
        log_rows = fetch_log_entries(cursor, logscan_id)
        structured = structure_logs_by_session(log_rows)

        for _, logs in structured.items():
            has_content = any((log.get("MATCHING_LINE") or "").strip() for log in logs)
            if has_content:
                session = parse_session_from_logs(logs, logscan_id)

               # if has_meaningful_data:
                upsert_session(cursor, session)


                latest_ts = max(log["SCAN_TIMESTAMP"] for log in logs if log["SCAN_TIMESTAMP"])
                if latest_ts > latest_processed_ts:
                    latest_processed_ts = latest_ts

    conn.commit()
    

    write_last_processed_ts(latest_processed_ts)
    print(f"[INFO] Updated last_processed_timestamp.txt to: {latest_processed_ts}")

    cursor.close()
    conn.close()

    print("[INFO] Session Audit Loader completed.")





if __name__ == "__main__":
    main()
