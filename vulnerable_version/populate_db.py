import sqlite3
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

import os
# Veritabanı bağlantısı oluştur (yoksa yaratır)
db = sqlite3.connect(os.getenv('SQLITE_PATH', 'scada.db'))
cursor = db.cursor()

# Tabloları oluştur
cursor.execute('DROP TABLE IF EXISTS users')
cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        details TEXT NOT NULL
    )
''')

# Admin kullanıcısı ekle
password_hash = generate_password_hash('admin123')
password_hash2 = generate_password_hash('test123')

cursor.execute("INSERT INTO users (id, username, password_hash) VALUES (1, 'admin', ?)", (password_hash,))
cursor.execute("INSERT INTO users (id, username, password_hash) VALUES (2, 'test', ?)", (password_hash2,))

# 100 adet rastgele log kaydı oluştur
event_types = ['Injection Change', 'Tank Refill', 'Safety Lock Trigger', 'System Startup', 'Manual Override']
details_templates = [
    "Rate changed to {} ml/min",
    "Tank level at {}%",
    "Pressure threshold exceeded: {} bar",
    "Routine check completed",
    "Operator ID {} performed action"
]

start_date = datetime.now() - timedelta(days=10)

print("Veritabanı dolduruluyor...")
for i in range(100):
    random_date = start_date + timedelta(minutes=random.randint(1, 14400))
    timestamp = random_date.strftime("%Y-%m-%d %H:%M:%S")
    
    e_type = random.choice(event_types)
    
    if e_type == 'Injection Change':
        detail = details_templates[0].format(random.randint(5, 50))
    elif e_type == 'Tank Refill':
        detail = details_templates[1].format(random.randint(80, 100))
    elif e_type == 'Safety Lock Trigger':
        detail = details_templates[2].format(random.randint(10, 15))
    elif e_type == 'Manual Override':
        detail = details_templates[4].format(random.randint(100, 105))
    else:
        detail = details_templates[3]
        
    cursor.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                   (timestamp, e_type, detail))

db.commit()
print(f"Başarılı! {i+1} kayıt eklendi. 'scada.db' oluşturuldu.")
db.close()