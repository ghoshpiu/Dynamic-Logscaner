# To fully adjust the script so that it writes detailed scan results to Snowflake,
# including the log file name, the line number, the matching line, and the timestamp of when the scan was conducted,
# we can extend the Snowflake integration to store this information. Additionally, we will create a table to store scan results.
# Adjusted Python Script for Detailed Logging to Snowflake

import os
import re
import snowflake.connector
import uuid
from datetime import datetime
from tqdm import tqdm 
import json
import csv

warehouse = "CTI_OTHER"
PARAMETER_FILE = os.path.join(os.path.dirname(__file__), "last_run_timestamps.json")




def load_scan_parameters(json_filename="scan_parameters.json"):
    script_dir = os.path.dirname(__file__)  # same logic as PARAMETER_FILE
    json_path = os.path.join(script_dir, json_filename)
    print(f"[DEBUG] Reading scan parameters from: {json_path}")
    with open(json_path, "r") as f:
        return json.load(f)


# Read last run timestamp from the parameter file
def read_last_run_timestamp(system_type):
    if not os.path.exists(PARAMETER_FILE):
        return datetime.strptime("01-01-1970 00:00:00", "%d-%m-%Y %H:%M:%S")

    with open(PARAMETER_FILE, "r") as f:
        try:
            data = json.load(f)
            ts_str = data.get(system_type)
            if ts_str:
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print(f"[WARN] Failed to read timestamp for {system_type}: {e}")

    return datetime.strptime("01-01-1970 00:00:00", "%d-%m-%Y %H:%M:%S")



# Update parameter file with the new latest timestamp
def update_last_run_timestamp(system_type, new_timestamp):
    data = {}
    if os.path.exists(PARAMETER_FILE):
        try:
            with open(PARAMETER_FILE, "r") as f:
                data = json.load(f)
        except:
            pass

    data[system_type] = new_timestamp.strftime("%Y-%m-%d %H:%M:%S")

    with open(PARAMETER_FILE, "w") as f:
        json.dump(data, f, indent=2)



# Snowflake setup for storing processed files and scan results
def setup_snowflake_connection():
    # Replace with your Snowflake credentials and configurations
    conn = snowflake.connector.connect(
        user='svc_python',
        password='Fb0Ie14bBdgsIducn1',
        account= 'CPTECHPARTNERORG-CPTECHPARTNER',
        warehouse='CTI_OTHER',
        database='CTI_AUDIT_FW',
        schema='CTI_AUDIT',
        role='CTI_AUDIT_ADMIN'
    )
    return conn


# Function to check if a file has been processed (using Snowflake)
def is_file_processed(file_name, conn):
    cursor = conn.cursor()

    # # Set the warehouse for the session
    # warehouse = 'CTI_OTHER'
    # cursor.execute(f"USE WAREHOUSE {warehouse}")

    # Check if the file is already in the processed_files table
    cursor.execute("SELECT COUNT(*) FROM CTI_AUDIT_FW.CTI_AUDIT.PROCESSED_LOGFILES WHERE FILE_NAME = %s", (file_name,))
    result = cursor.fetchone()
    cursor.close()

    return result[0] > 0


# Function to mark a file as processed in Snowflake
def mark_file_processed(file_name, conn):
    cursor = conn.cursor()

    # # Set the warehouse for the session
    # warehouse = 'CTI_OTHER'
    # cursor.execute(f"USE WAREHOUSE {warehouse}")

    # Insert the processed file into the table
    cursor.execute("INSERT INTO CTI_AUDIT_FW.CTI_AUDIT.PROCESSED_LOGFILES (FILE_NAME) VALUES (%s)", (file_name,))
    conn.commit()
    cursor.close()


# Function to log scan results to Snowflake
def log_scan_result(file_id,file_name, line_number, log_timestamp, matching_line,system_type, conn):
    # Generate a unique ID for the scan result
    #result_id = str(uuid.uuid4())

    cursor = conn.cursor()

    # # Set the warehouse for the session
    # warehouse = 'CTI_OTHER'
    cursor.execute(f"USE WAREHOUSE {warehouse}")

    # Insert the scan result into the scan_results table
    cursor.execute("""
        INSERT INTO CTI_AUDIT_FW.CTI_AUDIT.LOGSCAN_RESULTS (ID, FILE_NAME, LINE_NUMBER, LINE_TIMESTAMP, MATCHING_LINE,SYSTEM_TYPE)
        VALUES (%s, %s, %s, %s, %s,%s)
    """, (file_id, file_name, line_number, log_timestamp, matching_line,system_type))

    conn.commit()
    cursor.close()


# Function to scan a single log file for multiple keywords, timestamp range, and regex
def scan_log_file(log_file_path, search_keywords,system_type, start_time=None, end_time=None, use_regex=False, conn=None):
    print(f"[DEBUG] Processing system type: {system_type}")

    # Check if the log file exists
    if not os.path.exists(log_file_path):
        print(f"Error: The log file {log_file_path} does not exist.")
        return

    # Parse the timestamp range if provided
    start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S") if start_time else None
    end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") if end_time else None

    # Regular expression to match the timestamp pattern
    timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})'

    file_id = str(uuid.uuid4())

    with open(log_file_path, 'r', encoding='utf-8') as log_file:
        line_number = 0
        found_lines = False
          
        #logic to parse cexcel format file 
        if system_type.upper() in ["CDGC", "EXCEL"] or log_file_path.lower().endswith('.csv'):
            # CSV-style structured logs for CDGC
            reader = csv.reader(log_file)
            headers = next(reader, None)  # Skip the header row

            for row in reader:
                line_number += 1

                        
                if not row or len(row) != len(headers):
                    continue  # skip malformed rows

                # Build a dictionary: header -> value
                row_dict = dict(zip(headers, row))

                # Combine row into JSON string
                combined_line = json.dumps(row_dict)
                
                #combined_line = " ".join(row).lower()

                # Extract timestamp (first column)
                #log_timestamp = row[0].strip() if row and re.match(r'\d{4}-\d{2}-\d{2}', row[0]) else None
                log_timestamp = None
                for col in row:
                    if re.match(r'\d{4}-\d{2}-\d{2}', col.strip()):
                        log_timestamp = col.strip()
                        break


                if start_time and log_timestamp and log_timestamp < start_time:
                    continue
                if end_time and log_timestamp and log_timestamp > end_time:
                    continue

                #if any(keyword in combined_line for keyword in search_keywords):
                found_lines = True
                print(f"[{log_file_path}] Line {line_number}: {combined_line}")
                log_scan_result(file_id, log_file_path, line_number, log_timestamp, combined_line, system_type, conn)

        else:
            # Default for flat logs (INFA, etc.)
            for line in log_file:
                line_number += 1
                line = line.lower()

                if not line.startswith('===='):
                    match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', line)
                    log_timestamp = match.group(1) if match else None

                    if start_time and log_timestamp and log_timestamp < start_time:
                        continue
                    if end_time and log_timestamp and log_timestamp > end_time:
                        continue

                    if any(keyword in line for keyword in search_keywords) or (
                            use_regex and any(re.search(keyword, line) for keyword in search_keywords)):
                        found_lines = True
                        print(f"[{log_file_path}] Line {line_number}: {line.strip()}")
                        log_scan_result(file_id, log_file_path, line_number, log_timestamp, line.strip(), system_type, conn)

        if not found_lines:
            print(f"No matches found in {log_file_path} for the given search criteria.")



# Function to scan all log files in a directory
def scan_log_directory(directory_path, search_keywords,system_type, start_time=None, end_time=None, use_regex=False,
                       skip_processed_files=False, conn=None):
    
    print(f"[DEBUG] Attempting to scan: {directory_path}")

    # Check if the directory exists
    if not os.path.isdir(directory_path):
        print(f"Error: The directory {directory_path} does not exist.")
        return
    
    #file_filter_timestamp_str = input("Enter a file modified after timestamp (DD-MM-YYYY HH:MM) or press Enter to skip: ").strip()
    #file_filter_timestamp = None
    #if file_filter_timestamp_str:
        #try:
            #file_filter_timestamp = datetime.strptime(file_filter_timestamp_str, "%d-%m-%Y %H:%M")
        #except ValueError:
            #print("Invalid timestamp format. Expected format: DD-MM-YYYY HH:MM")
            #return
    #file_filter_timestamp = read_last_run_timestamp()
    #print(f"\n[INFO] Scanning files modified after: {file_filter_timestamp}")

    file_filter_timestamp = read_last_run_timestamp(system_type)
    print(f"[DEBUG] For system '{system_type}', using file filter timestamp: {file_filter_timestamp} (default if file missing)")

    print(f"\n[INFO] Scanning files modified after: {file_filter_timestamp}")



    # Define the list of allowed file extensions
    allowed_extensions = ('.log', '.txt', '.csv', '.json', '.xml')  # Add any other extensions you need

    # List all log files in the directory
    #log_files = [f for f in os.listdir(directory_path) if f.endswith(allowed_extensions)]
    log_files=[os.path.join(directory_path, f) for f in os.listdir(directory_path)
                 if os.path.isfile(os.path.join(directory_path, f)) and f.endswith(allowed_extensions)]


    print("\n[DEBUG] Listing all files with timestamps:")

    for file_path in log_files:
        modified_time = datetime.fromtimestamp(os.path.getmtime(file_path))
        condition = modified_time > file_filter_timestamp
        print(f"  - {file_path} | Last Modified: {modified_time}  Condition is passing? {datetime.fromtimestamp(os.path.getmtime(file_path)) > file_filter_timestamp}")

    filtered_files = []
    max_processed_timestamp = file_filter_timestamp

    for file_path in log_files:
        modified_time = datetime.fromtimestamp(os.path.getmtime(file_path))
        if modified_time > file_filter_timestamp:
            filtered_files.append(file_path)
            if modified_time > max_processed_timestamp:
                max_processed_timestamp = modified_time

    if not filtered_files:
        print("No files matched the modified timestamp filter.")
        return

    print("\n[DEBUG] Files selected for scanning (sorted newest to oldest):")
    for file_path in filtered_files:
        print(f"  - {file_path} | Last Modified: {datetime.fromtimestamp(os.path.getmtime(file_path))}")


    # Initialize the progress bar
    with tqdm(total=len(filtered_files), desc="Scanning files", unit="file") as pbar:
        # Loop through all files in the directory
        #for filename in filtered_files:
            #log_file_path = os.path.join(directory_path, filename)
          # Loop through all filtered files (they already have full path)
        for log_file_path in filtered_files:
            # Skip processed files if enabled
            if skip_processed_files and is_file_processed(os.path.basename(log_file_path), conn):
                pbar.update(1)  # Update the progress bar even if we skip the file
                continue

            print(f"\nScanning file: {log_file_path}")
            # Call scan_log_file function for each log file
            scan_log_file(log_file_path, search_keywords,system_type, start_time, end_time, use_regex, conn)

            # After processing, mark the file as processed in Snowflake
            if skip_processed_files:
                mark_file_processed(os.path.basename(log_file_path), conn)

            pbar.update(1)  # Update the progress bar
      
    # Update the parameter file with latest processed timestamp
    update_last_run_timestamp(system_type,max_processed_timestamp)
    print(f"\n[INFO] Updated parameter file with new timestamp: {max_processed_timestamp}")
    



# Main function
def main():
    # Set up Snowflake connection
    conn = setup_snowflake_connection()

    # Load parameter sets
    parameter_sets = load_scan_parameters("scan_parameters.json")
   
    # Loop through each log type (INFA, CDGC, etc.)
    for param in parameter_sets:
        system_type = param["SYSTEM_TYPE"]
        directory_path = param["LOG_FILE_PATH"]
        search_keywords = [kw.strip().lower() for kw in param["KEY_WORDS"].split(",")]

        #use_regex = input("Do you want to use regex for pattern matching? (yes/no): ").strip().lower() == 'yes'
        use_regex= True # Bypassing to make it dynamic 


        # Timestamp filtering
        #start_time = input("Enter the start timestamp (YYYY-MM-DD HH:MM:SS) or press Enter to skip: ")
        #end_time = input("Enter the end timestamp (YYYY-MM-DD HH:MM:SS) or press Enter to skip: ")
        start_time = None  # this is also hard-coded to make it dynamic
        end_time = None    # same for this , to make it dynamic


        # Skip previously processed files (to avoid reprocessing)
        #skip_processed_files = input("Do you want to skip already processed files? (yes/no): ").strip().lower() == 'yes'
        skip_processed_files = False # is made false to allow incremental loading logic 
        #Timestamp filtering for directory
        print("Log Scan Tool - Enhanced with File Modified Time Filter\n")



        # Call the function to scan all log files in the directory
        scan_log_directory(directory_path, search_keywords, system_type, start_time, end_time, use_regex, skip_processed_files, conn)

    # Close the Snowflake connection once all systems are processed
    conn.close()



if __name__ == "__main__":
    main()
