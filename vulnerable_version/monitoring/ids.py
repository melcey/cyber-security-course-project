import sqlite3
from datetime import datetime, timedelta
from flask import request, session

# Global in-memory storage for rate limiting (IDS state)
login_attempts = {} # {ip: [timestamps]}
scan_attempts = {}  # {ip: [timestamps]}

# Database Connection for Monitoring
def get_monitor_db():
    conn = sqlite3.connect('scada.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize tables
def init_monitoring_table():
    conn = get_monitor_db()
    try:
        # Attack Logs
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                ip_address TEXT,
                attack_type TEXT,
                payload TEXT,
                endpoint TEXT,
                classification TEXT,
                recommended_action TEXT,
                severity TEXT
            )
        ''')
        # Banned IPs (Automated Response)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip_address TEXT PRIMARY KEY,
                reason TEXT,
                timestamp TEXT
            )
        ''')
    except Exception as e:
        print(f"DB Init Warning: {e}")
        
    conn.commit()
    conn.close()

# Helper: Clean up old timestamps
def cleanup_attempts(attempts, window_seconds=60):
    now = datetime.now()
    cutoff = now - timedelta(seconds=window_seconds)
    for ip in list(attempts.keys()):
        attempts[ip] = [t for t in attempts[ip] if t > cutoff]
        if not attempts[ip]:
            del attempts[ip]

# Auto-Ban Helper
def ban_ip(ip, reason):
    try:
        conn = get_monitor_db()
        conn.execute("INSERT OR IGNORE INTO banned_ips (ip_address, reason, timestamp) VALUES (?, ?, ?)", 
                     (ip, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        print(f"!!! AUTOMATED DEFENSE: Banned IP {ip} due to {reason} !!!")
    except Exception as e:
        print(f"Ban failed: {e}")

# Check if IP is Banned
def is_ip_banned(ip):
    try:
        conn = get_monitor_db()
        row = conn.execute("SELECT * FROM banned_ips WHERE ip_address = ?", (ip,)).fetchone()
        conn.close()
        return row is not None
    except:
        return False

# MAIN DETECTION LOGIC
def check_for_attacks():
    # 0. Pre-Flight Check: Is IP already banned? (Optional optimization, but app.py handles enforcement)
    if is_ip_banned(request.remote_addr):
        return # Already handled by app.py middleware

    detected_attack = None
    attack_type = ""
    malicious_payload = ""
    classification = ""
    action = ""
    severity = "Low"

    # 1. Signatures
    ssti_patterns = ['{{', '}}', '__class__', '__base__', '__subclasses__', 'config.', 'request.']
    sqli_patterns = ["'--", "' OR", "' UNION", "UNION SELECT", "DROP TABLE", "INSERT INTO", "xp_cmdshell", "1=1", ";--", "sleep(", "benchmark(", "waitfor delay", "@@version", "load_file"]
    path_patterns = ['../', '..\\', '/etc/passwd', 'win.ini', '.env']
    scan_patterns = ['.env', '.git', 'wp-admin', 'phpmyadmin', '.bak', '.old', '.cfg', 'admin.php']
    # Known Hacking Tools (User-Agents)
    tool_patterns = ['sqlmap', 'nikto', 'burp', 'metasploit', 'nmap', 'python-requests', 'curl', 'wget', 'go-http-client']

    # 2. Collect Data
    data_to_check = []
    for key, value in request.args.items(): data_to_check.append(value)
    for key, value in request.form.items(): data_to_check.append(value)
    
    # 3a. User-Agent Investigation (Automated Tools)
    if not detected_attack:
        ua = request.user_agent.string.lower()
        for tool in tool_patterns:
            if tool in ua:
                detected_attack = "Automated Hacking Tool Detected"
                classification = "Reconnaissance / Scanning"
                action = "Automated Ban Triggered"
                severity = "Medium"
                malicious_payload = f"User-Agent: {ua}"
                break

    # 3b. SCADA Logic Integrity (Parameter Tampering)
    if not detected_attack and 'level_value' in request.form:
        try:
            val = int(request.form['level_value'])
            # Logic Rule: Level must be 0-100
            if val < 0 or val > 100:
                detected_attack = "SCADA Logic Violation"
                classification = "Parameter Tampering"
                action = "Automated Ban Triggered"
                severity = "High"
                malicious_payload = f"Illegal Tank Level: {val}%"
        except:
             pass # Non-integer values caught by SQLi/SSTI checks usually

    # 3c. Cookie Investigation
    if not detected_attack:
        for curr_cookie in request.cookies:
            cookie_val = request.cookies.get(curr_cookie)
            for pat in sqli_patterns + ssti_patterns:
                if pat in cookie_val:
                    detected_attack = "Cookie Manipulation"
                    classification = "Session/Auth Attack"
                    action = "Automated Ban Triggered"
                    severity = "High"
                    malicious_payload = f"Cookie {curr_cookie}={cookie_val}"
                    break
            if detected_attack: break

    # 4. Brute Force (Login)
    if not detected_attack and request.path == '/login' and request.method == 'POST':
        ip = request.remote_addr
        now = datetime.now()
        cleanup_attempts(login_attempts)
        if ip not in login_attempts: login_attempts[ip] = []
        login_attempts[ip].append(now)
        
        if len(login_attempts[ip]) > 5:
            detected_attack = "Login Brute Force"
            classification = "Authentication Attack"
            action = "Automated Ban Triggered"
            severity = "Medium"
            malicious_payload = f"Excessive Login Attempts: {len(login_attempts[ip])}"

    # 5. Directory Scanning
    if not detected_attack:
        for pattern in scan_patterns:
            if pattern in request.path:
                detected_attack = "Directory Scanning"
                classification = "Reconnaissance"
                action = "Automated Ban Triggered"
                severity = "Medium"
                malicious_payload = request.path
                break
            
    # 6. Payload Detection
    if not detected_attack:
        for data in data_to_check:
            if not isinstance(data, str): continue
            
            # SSTI
            for pattern in ssti_patterns:
                if pattern in data:
                    detected_attack = "SSTI (Template Injection)"
                    classification = "Code Injection"
                    action = "Automated Ban Triggered"
                    severity = "Critical"
                    malicious_payload = data
                    break
            
            # SQLi
            if not detected_attack:
                for pattern in sqli_patterns:
                    if pattern.lower() in data.lower():
                        detected_attack = "SQL Injection"
                        classification = "Database Injection"
                        action = "Automated Ban Triggered"
                        severity = "Critical"
                        malicious_payload = data
                        break

            # Path Traversal
            if not detected_attack:
                for pattern in path_patterns:
                    if pattern in data:
                        detected_attack = "Path Traversal"
                        classification = "File System Access"
                        action = "Automated Ban Triggered"
                        severity = "High"
                        malicious_payload = data
                        break
            
            if detected_attack: break

    # 7. CSRF Detection
    critical_endpoints = ['/emergency_stop', '/start_system', '/change_rate', '/set_tank_level']
    if not detected_attack and request.method == 'POST' and request.path in critical_endpoints:
        referer = request.headers.get("Referer", "")
        origin = request.headers.get("Origin", "")
        host = request.host
        
        is_trusted = False
        if referer and host in referer: is_trusted = True
        elif origin and host in origin: is_trusted = True
        
        if not is_trusted:
            detected_attack = "CSRF Attempt"
            classification = "Session/Auth Attack"
            action = "Automated Ban Triggered"
            severity = "High"
            ref_status = referer if referer else (origin if origin else "MISSING")
            malicious_payload = f"Untrusted Source: {ref_status}"

    # 8. Log & Respond
    if detected_attack:
        try:
            conn = get_monitor_db()
            conn.execute('''
                INSERT INTO attack_logs (timestamp, ip_address, attack_type, payload, endpoint, classification, recommended_action, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                request.remote_addr,
                detected_attack,
                malicious_payload,
                request.path,
                classification,
                action,
                severity
            ))
            conn.commit()
            conn.close()
            print(f"[ALERT] {detected_attack} Detected from {request.remote_addr}!")
            
            # AUTOMATED ACTION: BAN IP
            if severity in ['Medium', 'High', 'Critical']:
                ban_ip(request.remote_addr, f"Auto-Ban: {detected_attack}")
                
        except Exception as e:
            print(f"[ERROR] Failed to log/ban: {e}")
