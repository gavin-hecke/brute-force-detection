# brute-force-detection
A simple Python tool that analyzes login logs using pandas DataFrames to detect potential brute-force login attempts based on a user-defined failure threshold and time window. Built to practice data manipulation and time-based analysis with pandas.

**Features**
Parses JSON-formatted login logs
Filters failed login attempts
Uses a sliding time window to detect suspicious behavior
Outputs flagged IP addresses to a CSV file

**Usage**
python detect_bruteforce.py --input sample_logs.json --output suspicious_ips.csv

After running, the script will prompt you to enter:
Fail threshold (number of failed attempts before flagging)
Time window in minutes (within which failures are counted)

Example
If an IP address fails to log in 5 times within 5 minutes, it will be flagged and written to the output CSV.

**Requirements**
Python 3
pandas


