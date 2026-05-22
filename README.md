SSH Brute Force Detector
Monitors /var/log/auth.log for failed SSH login attempts. Flags IPs exceeding a configurable failure threshold (e.g., 5 attempts/minute). Blocks offenders via iptables or sends alerts. Lightweight and runs as a background service.
