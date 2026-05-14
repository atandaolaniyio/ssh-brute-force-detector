#!/usr/bin/env python3
"""
SSH Brute Force Detector
Detects multiple failed SSH login attempts from single IP addresses
"""

import re
import sys
from collections import defaultdict
from datetime import datetime

def parse_auth_log(log_path):
    """Parse auth.log and count failed SSH attempts by IP"""
    failed_attempts = defaultdict(list)
    
    try:
        with open(log_path, 'r') as log_file:
            for line in log_file:
                # Look for failed password attempts
                if 'Failed password' in line and 'ssh' in line.lower():
                    # Extract IP address
                    ip_match = re.search(r'from ([\d\.]+)', line)
                    # Extract timestamp
                    time_match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                    
                    if ip_match:
                        ip = ip_match.group(1)
                        timestamp = time_match.group(1) if time_match else "unknown"
                        failed_attempts[ip].append(timestamp)
    except FileNotFoundError:
        print(f"❌ Error: File '{log_path}' not found")
        sys.exit(1)
    
    return failed_attempts

def generate_report(failed_attempts, threshold=5):
    """Generate alert report for IPs exceeding threshold"""
    alerts = []
    
    for ip, timestamps in failed_attempts.items():
        count = len(timestamps)
        if count >= threshold:
            alerts.append({
                'ip': ip,
                'count': count,
                'timestamps': timestamps[:5]  # Show first 5 attempts
            })
    
    return alerts

def main():
    print("🔍 SSH Brute Force Detector")
    print("=" * 40)
    
    # Default log path for Linux systems
    log_path = "/var/log/auth.log"
    
    # Allow custom path as argument
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    
    print(f"📂 Analyzing: {log_path}")
    
    # Parse the log
    failed_attempts = parse_auth_log(log_path)
    
    if not failed_attempts:
        print("✅ No failed SSH attempts found.")
        return
    
    total_failures = sum(len(timestamps) for timestamps in failed_attempts.values())
    print(f"📊 Total failed attempts: {total_failures}")
    print(f"🌐 Unique attacking IPs: {len(failed_attempts)}")
    
    # Generate alerts
    alerts = generate_report(failed_attempts, threshold=5)
    
    if alerts:
        print("\n🚨 ALERTS: Potential brute force attacks detected!")
        print("-" * 40)
        for alert in alerts:
            print(f"⚠️  IP: {alert['ip']} - {alert['count']} failed attempts")
            print(f"   First 5 attempts at: {', '.join(alert['timestamps'])}")
            print()
    else:
        print("\n✅ No IPs exceeded the threshold of 5 failures.")
    
    # Save CSV report
    import csv
    with open('bruteforce_report.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Failed Attempts', 'First Attempt', 'Last Attempt'])
        for ip, timestamps in failed_attempts.items():
            writer.writerow([
                ip, 
                len(timestamps), 
                timestamps[0] if timestamps else 'N/A',
                timestamps[-1] if timestamps else 'N/A'
            ])
    
    print(f"📄 Detailed report saved to: bruteforce_report.csv")

if __name__ == "__main__":
    main()
