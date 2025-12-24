import sqlite3
from datetime import datetime
from flask import request

# Database Connection for Monitoring
# Since app.py runs from the root folder, we can access 'scada.db' directly.
def get_monitor_db():
    conn = sqlite3.connect('scada.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the attack logs table
def init_monitoring_table():
    conn = get_monitor_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            ip_address TEXT,
            attack_type TEXT,
            payload TEXT,
            endpoint TEXT
        )
    ''')
    conn.commit()
    conn.close()

# MAIN DETECTION LOGIC
def check_for_attacks():
    # 1. Attack Signatures (Patterns to look for)
    # SSTI: Template syntax used in Jinja2
    ssti_patterns = ['{{', '}}', '__class__', '__base__', '__subclasses__', 'config.', 'request.']
    
    # SQLi: Common SQL injection payloads
    sqli_patterns = ["'--", "' OR", "' UNION", "UNION SELECT", "DROP TABLE", "INSERT INTO", "xp_cmdshell", "1=1", ";--", "sleep(", "benchmark(", "waitfor delay", "@@version", "load_file"]
    
    # 2. Collect Data to Inspect
    data_to_check = []
    # Check URL parameters (e.g., ?search=...)
    for key, value in request.args.items(): data_to_check.append(value)
    # Check Form data (e.g., POST inputs)
    for key, value in request.form.items(): data_to_check.append(value)

    # 3. Analyze Data
    detected_attack = None
    malicious_payload = ""

    for data in data_to_check:
        if not isinstance(data, str): continue
        
        # Check for SSTI
        for pattern in ssti_patterns:
            if pattern in data:
                detected_attack = "SSTI (Template Injection)"
                malicious_payload = data
                break
        
        # Check for SQLi (Case-insensitive)
        if not detected_attack:
            for pattern in sqli_patterns:
                if pattern.lower() in data.lower():
                    detected_attack = "SQL Injection"
                    malicious_payload = data
                    break
        
        if detected_attack: break

    # 4. Log Attack if Detected
    if detected_attack:
        try:
            conn = get_monitor_db()
            conn.execute('''
                INSERT INTO attack_logs (timestamp, ip_address, attack_type, payload, endpoint)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                request.remote_addr,
                detected_attack,
                malicious_payload,
                request.path
            ))
            conn.commit()
            conn.close()
            print(f"[ALERT] {detected_attack} Detected from {request.remote_addr}!")
        except Exception as e:
            print(f"[ERROR] Failed to log attack: {e}")