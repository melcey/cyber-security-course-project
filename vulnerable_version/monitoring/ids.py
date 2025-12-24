import sqlite3
from datetime import datetime
from flask import request

# Database Connection for Monitoring
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
    # 1. Signatures (Keeping your friends' original work intact)
    ssti_patterns = ['{{', '}}', '__class__', '__base__', '__subclasses__', 'config.', 'request.']
    sqli_patterns = ["'--", "' OR", "' UNION", "UNION SELECT", "DROP TABLE", "INSERT INTO", "xp_cmdshell", "1=1", ";--", "sleep(", "benchmark(", "waitfor delay", "@@version", "load_file"]
    
    # NEW: Path Traversal patterns (Requirement: File Path Injection)
    path_patterns = ['../', '..\\', '/etc/passwd', 'win.ini', '.env']
    
    # 2. Collect Data to Inspect
    data_to_check = []
    for key, value in request.args.items(): data_to_check.append(value)
    for key, value in request.form.items(): data_to_check.append(value)

    # 3. Analyze Data
    detected_attack = None
    malicious_payload = ""

    # A. Check for Payload-based attacks (SSTI, SQLi, Path Traversal)
    for data in data_to_check:
        if not isinstance(data, str): continue
        
        # Original SSTI Check
        for pattern in ssti_patterns:
            if pattern in data:
                detected_attack = "SSTI (Template Injection)"
                malicious_payload = data
                break
        
        # Original SQLi Check
        if not detected_attack:
            for pattern in sqli_patterns:
                if pattern.lower() in data.lower():
                    detected_attack = "SQL Injection"
                    malicious_payload = data
                    break

        # NEW: Path Traversal Check
        if not detected_attack:
            for pattern in path_patterns:
                if pattern in data:
                    detected_attack = "Path Traversal"
                    malicious_payload = data
                    break
        
        if detected_attack: break

    # B. NEW: CSRF Detection (Requirement: Missing CSRF on POST form)
    # We monitor critical endpoints for state-changing POST requests
    critical_endpoints = ['/emergency_stop', '/start_system', '/change_rate', '/set_tank_level']
    
    if not detected_attack and request.method == 'POST' and request.path in critical_endpoints:
        referer = request.headers.get("Referer", "")
        
        # LOGIC: If Referer is empty OR does not contain our trusted domain
        is_trusted = "127.0.0.1:5001" in referer or "localhost:5001" in referer
        
        if not referer or not is_trusted:
            detected_attack = "CSRF Attempt"
            # Log what the referer actually was (or if it was missing)
            ref_status = referer if referer else "MISSING (Potential Cross-Site/File Exploit)"
            malicious_payload = f"Untrusted Source. Referer: {ref_status}"

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