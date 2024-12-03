This submission includes a Python script that performs comprehensive log file analysis, meeting the requirements outlined in the VRV Security Python Intern Assignment. The script processes a web server log file to extract key insights related to cybersecurity. Below is an overview of its functionalities:

Requests Per IP Address:

Extracts and counts the number of requests made by each IP address from the log file.
Outputs the results in descending order of request counts for easy interpretation.
Most Frequently Accessed Endpoint:

Identifies the endpoint (e.g., URL or resource path) with the highest number of accesses.
Displays the endpoint name along with its access count.
Suspicious Activity Detection:

Detects potential brute force login attempts by analyzing failed login attempts (HTTP status code 401).
Flags IP addresses that exceed a configurable threshold of failed attempts (default: 10).
Output Results:

Presents all findings in the terminal for real-time feedback.
Saves results in a structured CSV file (log_analysis_results.csv) for documentation and further analysis.
Execution Instructions
Save the log file provided (sample.log) in the same directory as the script.
Run the script in a Python environment:
bash
Copy code
python log_analysis.py
The script will:
Display results in the terminal.
Save the analysis to log_analysis_results.csv.
Key Features
Efficient Parsing: Uses regex to extract relevant fields from the log file.
Clear Results: Outputs organized data to both terminal and CSV.
Scalability: Handles larger log files without significant performance overhead.
Customizable Threshold: Allows configuration of the failed login attempt threshold.
This script demonstrates proficiency in Python programming, with a focus on file handling, string manipulation, data analysis, and cybersecurity principles.
