from flask import Flask, render_template, request, redirect, url_for, session, send_file, render_template_string
import sqlite3
import os
from datetime import datetime

from monitoring.ids import init_monitoring_table, check_for_attacks, get_monitor_db

app = Flask(__name__)
app.secret_key = 'super_secret_key' # Required for session management

# --- Database Connection Helper ---
def get_db_connection():
    conn = sqlite3.connect('scada.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- Global SCADA Status (Simulation State) ---
# This dictionary simulates the physical state of the OT system (PLC/SCADA)
scada_status = {
    'tank_level': 85,          # Main Tank Level (%)
    'backup_tank_level': 100,  # Backup Tank Level (%)
    'active_tank': 'Main',     # Current Active Source: 'Main' or 'Backup'
    'injection_rate': 12,      # Chlorine Injection Rate (ml/min)
    'safety_lock': 'Normal',   # System Status Message
    'system_active': True      # Boolean: Is system running?
}

# =====================================================
# INTEGRATE MONITORING (MIDDLEWARE)
# =====================================================

# This function runs before EVERY request to the server.
# It acts as a firewall/IDS.
@app.before_request
def security_check():
    check_for_attacks() # Call logic from monitoring/ids.py

# =====================================================
# STANDARD ROUTES (Auth & Dashboard)
# =====================================================

# 1. Main Dashboard
@app.route('/')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', status=scada_status)

# 2. Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hardcoded credentials for simulation purposes
        if username == 'admin' and password == 'admin123':
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. (Try admin/admin123)'
    return render_template('login.html', error=error)

# 3. Logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/monitor')
def monitor_dashboard():
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    # Fetch attack logs using the helper from the monitoring module
    conn = get_monitor_db()
    attacks = conn.execute('SELECT * FROM attack_logs ORDER BY id DESC').fetchall()
    conn.close()
    
    return render_template('monitor.html', attacks=attacks)


# =====================================================
# VULNERABLE FUNCTIONS & SCADA LOGIC
# =====================================================

# --- VULNERABILITY POINT 1: SQL Injection ---
# Scenario: Search functionality in system logs.
# Flaw: User input is directly concatenated into the SQL query string using f-strings.
@app.route('/logs')
def view_logs():
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')
    conn = get_db_connection()
    
    if search_query:
        # [!] VULNERABLE CODE:
        # Attackers can inject SQL commands. Example: ' UNION SELECT 1,2,password,4 FROM users --
        query = f"SELECT * FROM logs WHERE details LIKE '%{search_query}%' ORDER BY timestamp DESC"
        print(f"[DEBUG] Executing SQL: {query}") 
        logs = conn.execute(query).fetchall()
    else:
        logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50').fetchall()
    
    conn.close()
    return render_template('logs.html', logs=logs)


# --- VULNERABILITY POINT 2: CSRF (Cross-Site Request Forgery) ---
# Scenario: Critical control functions (Emergency Stop, Rate Change, etc.)
# Flaw: No CSRF Token validation is implemented. Attackers can trigger these actions via malicious links.

@app.route('/emergency_stop', methods=['POST'])
def emergency_stop():
    if not session.get('logged_in'): return "Unauthorized!", 403
    
    # Update system state
    scada_status['system_active'] = False
    scada_status['safety_lock'] = 'TRIPPED (Emergency Stop)'
    scada_status['injection_rate'] = 0
    
    # Log the event
    conn = get_db_connection()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                 (timestamp, 'Safety Lock Trigger', 'Lock: TRIPPED (Emergency Stop)'))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/start_system', methods=['POST'])
def start_system():
    if not session.get('logged_in'): return "Unauthorized!", 403

    # Update system state
    scada_status['system_active'] = True
    scada_status['safety_lock'] = 'Normal'
    scada_status['injection_rate'] = 12
    
    # Log the event
    conn = get_db_connection()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                 (timestamp, 'Safety Lock Trigger', 'Lock: Normal'))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/switch_to_backup', methods=['POST'])
def switch_to_backup():
    if not session.get('logged_in'): return "Unauthorized", 403
    
    # Logic Check: Only allow switch if system is currently stopped
    if not scada_status['system_active']:
        scada_status['active_tank'] = 'Backup'
        scada_status['system_active'] = True 
        scada_status['safety_lock'] = 'Backup Active'
        
        # Log the event
        conn = get_db_connection()
        conn.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'System Alert', 'Switched to Backup Tank'))
        conn.commit()
        conn.close()
        
    return redirect(url_for('dashboard'))

@app.route('/set_tank_level', methods=['POST'])
def set_tank_level():
    if not session.get('logged_in'): return "Unauthorized", 403
    
    try:
        new_level = int(request.form['level_value'])
        tank_type = request.form['tank_type'] # 'main' or 'backup'
        
        if 0 <= new_level <= 100:
            log_detail = ""
            if tank_type == 'main':
                scada_status['tank_level'] = new_level
                log_detail = f"Main Tank refill (at {new_level}%)"
            elif tank_type == 'backup':
                scada_status['backup_tank_level'] = new_level
                log_detail = f"Backup Tank refill (at {new_level}%)"
            
            # Log the event
            conn = get_db_connection()
            conn.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                         (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Tank Refill', log_detail))
            conn.commit()
            conn.close()
            
    except (ValueError, KeyError):
        pass

    return redirect(url_for('dashboard'))

@app.route('/change_rate', methods=['POST'])
def change_rate():
    if not session.get('logged_in'): return "Unauthorized", 403
    
    action = request.form.get('action')
    log_detail = ""
    
    if action == 'increase':
        scada_status['injection_rate'] += 2
        log_detail = "Injection rate increased 2 ml/min"
    elif action == 'decrease' and scada_status['injection_rate'] >= 2:
        scada_status['injection_rate'] -= 2
        log_detail = "Injection rate decreased 2 ml/min"
        
    # Log the event
    if log_detail:
        conn = get_db_connection()
        conn.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Injection Change', log_detail))
        conn.commit()
        conn.close()
        
    return redirect(url_for('dashboard'))


# --- VULNERABILITY POINT 3: Path Traversal (Arbitrary File Download) ---
# Scenario: Exporting system logs.
# Flaw: No input sanitization on the 'file' parameter.
@app.route('/download_log')
def download_log():
    if not session.get('logged_in'): return redirect(url_for('login'))

    filename = request.args.get('file')
    log_dir = 'system_logs' 

    # Feature: If 'daily.log' is requested, generate it dynamically with today's DB data
    if filename == 'daily.log':
        try:
            today_str = datetime.now().strftime("%Y-%m-%d")
            
            conn = get_db_connection()
            # Fetch logs starting with today's date
            logs = conn.execute(f"SELECT * FROM logs WHERE timestamp LIKE '{today_str}%' ORDER BY timestamp DESC").fetchall()
            conn.close()

            # Write to file
            file_path = os.path.join(log_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"--- SCADA SYSTEM DAILY LOGS: {today_str} ---\n")
                f.write(f"Generated at: {datetime.now().strftime('%H:%M:%S')}\n")
                f.write("-" * 50 + "\n\n")
                if not logs:
                    f.write("No events recorded today.\n")
                else:
                    for log in logs:
                        f.write(f"[{log['timestamp']}] {log['event_type']}: {log['details']}\n")
        except Exception as e:
            print(f"[ERROR] Log generation failed: {e}")

    # [!] VULNERABLE CODE:
    # Directly joins user input with the directory.
    # Payload Example: download_log?file=../../app.py
    file_path = os.path.join(log_dir, filename)
    
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return f"File not found: {file_path}", 404


# --- VULNERABILITY POINT 4: SSTI (Server-Side Template Injection) ---
# Scenario: Generating a quick preview report.
# Flaw: User input is rendered directly using render_template_string without escaping.
@app.route('/report_preview')
def report_preview():
    if not session.get('logged_in'): return redirect(url_for('login'))

    tank_name = request.args.get('tank_name', 'Main Tank')

    # [!] VULNERABLE CODE:
    # Payload Example: {{ 7*7 }} or {{ config.items() }}
    template_content = f"""
    <h1>Report Preview</h1>
    <p>Selected Tank: <b>{tank_name}</b></p>
    <p>Current Level: {scada_status['tank_level']}%</p>
    <p>Status: {scada_status['safety_lock']}</p>
    """
    
    return render_template_string(template_content)


if __name__ == '__main__':
    # Running on port 5001 as per configuration
    app.run(host='0.0.0.0', port=5001, debug=True)