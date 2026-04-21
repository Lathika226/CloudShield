import datetime
import re

LOG_FILE = "logs.txt"

def log_attack(payload, attack_type):
    """Log blocked attacks with timestamp."""
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] BLOCKED - Type: {attack_type} - Payload: {payload}\n")

def analyze_payload(payload):
    """
    Main project brain for detection.
    Analyzes the payload for potential security threats.
    """
    # Check for SQL Injection
    sql_patterns = [r"drop\s+table", r"select\s+.*\s+from", r"union\s+select", r"or\s+1=1"]
    for pattern in sql_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            log_attack(payload, "SQL Injection")
            return False, "SQL Injection Detected"
    
    # Check for Cross-Site Scripting (XSS)
    xss_patterns = [r"<script>", r"javascript:", r"onerror="]
    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            log_attack(payload, "Cross-Site Scripting (XSS)")
            return False, "XSS Detected"
    
    return True, "Safe"
