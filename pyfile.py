import re
import csv
from collections import Counter, defaultdict

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
LOG_PATTERN = r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*? "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d\.\d" (?P<status>\d+)'
FAILED_LOGIN_STATUS = "401"

def parse_log(file_path):
    log_data = []
    with open(file_path, "r") as file:
        for line in file:
            match = re.search(LOG_PATTERN, line)
            if match:
                log_data.append(match.groupdict())
    return log_data

def count_requests_per_ip(log_data):
    ip_counter = Counter(entry["ip"] for entry in log_data)
    return ip_counter.most_common()

def most_frequently_accessed_endpoint(log_data):
    endpoint_counter = Counter(entry["endpoint"] for entry in log_data)
    return endpoint_counter.most_common(1)[0]

def detect_suspicious_activity(log_data):
    failed_attempts = defaultdict(int)
    for entry in log_data:
        if entry["status"] == FAILED_LOGIN_STATUS:
            failed_attempts[entry["ip"]] += 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_to_csv(ip_requests, most_accessed, suspicious_ips, file_path):
    with open(file_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_data = parse_log(LOG_FILE)
    ip_requests = count_requests_per_ip(log_data)
    print("Requests per IP Address:")
    for ip, count in ip_requests:
        print(f"{ip:20} {count}")
    most_accessed = most_frequently_accessed_endpoint(log_data)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    suspicious_ips = detect_suspicious_activity(log_data)
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")
    save_to_csv(ip_requests, most_accessed, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
