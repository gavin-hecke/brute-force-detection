import json
import pandas as pd
from datetime import datetime, timedelta
import argparse

# detect brute-force login attempts based on failed logins through number of attempts and time
def detect_brute_force(logs, fail_threshold=5, window_minutes=5):

    # Convert raw logs to a pandas DataFrame 
    df = pd.DataFrame(logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df[df['status'] == 'FAIL']

    # Sort by timestamp (inplace modifies the dataframe)
    df.sort_values(by='timestamp', inplace=True)

    suspicious_ips = []

    # Iterate over each unique IP address that had failed logins
    for ip in df['ip'].unique():

        # grabs all failed attempts for current ip in loop
        ip_df = df[df['ip'] == ip]  

        for i in range(len(ip_df)):

            # have to do it like this so
            start_time = ip_df.iloc[i]['timestamp']
            end_time = start_time + timedelta(minutes=window_minutes)

            # all failed attempts from this IP within the time window
            window_df = ip_df[(ip_df['timestamp'] >= start_time) & (ip_df['timestamp'] <= end_time)]

            # If the number of failed attempts in the window exceeds the threshold flag it and break loop
            if len(window_df) >= fail_threshold:
                suspicious_ips.append({
                    "ip": ip,
                    "failed_logins": len(window_df),
                    "time_window_start": start_time.isoformat(),
                    "time_window_end": end_time.isoformat()
                })
                break

    return suspicious_ips 


def main():

    parser = argparse.ArgumentParser(description="Detect brute-force login attempts from log file.")
    parser.add_argument("--input", required=True, help="Path to input JSON log file")
    parser.add_argument("--output", required=True, help="Path to output CSV for suspicious IPs")
    args = parser.parse_args()

    # Load the input log file (json format for this project)
    with open(args.input) as f:
        logs = json.load(f)


    fail_threshold = int(input("Enter fail threshold: "))
    window_minutes = int(input("Enter window in minutes to look through: "))
    results = detect_brute_force(logs, fail_threshold, window_minutes)

    # save to a CSV, unless no activity is detected then print no activity was detected
    if results:
        pd.DataFrame(results).to_csv(args.output, index=False)
        print(f"\nSuspicious activity written to {args.output}")
    else:
        print("\nNo suspicious activity detected.")

if __name__ == "__main__":
    main()