import sqlite3
import random
from datetime import datetime, timedelta

# Veritabanı bağlantısı oluştur
db = sqlite3.connect('scada.db')
cursor = db.cursor()

# Tabloları oluştur (Eğer yoksa)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
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
cursor.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')")

# --- GÜNCELLENMİŞ LOG MANTIĞI ---
# Sadece istenilen 3 ana kategori
event_types = ['Injection Change', 'Tank Refill', 'Safety Lock Trigger']

start_date = datetime.now() - timedelta(days=10)

print("Veritabanı yeni log formatlarıyla dolduruluyor...")

for i in range(100):
    # Son 10 gün içinde rastgele bir zaman
    random_date = start_date + timedelta(minutes=random.randint(1, 14400))
    timestamp = random_date.strftime("%Y-%m-%d %H:%M:%S")
    
    e_type = random.choice(event_types)
    detail = ""

    if e_type == 'Injection Change':
        # Artış veya azalış (2 ml/min sabit)
        action = random.choice(['increased', 'decreased'])
        detail = f"Injection rate {action} 2 ml/min"
        
    elif e_type == 'Tank Refill':
        # Rastgele bir seviye yüzdesi
        level = random.randint(20, 95)
        detail = f"Tank refill (at {level}%)"
        
    elif e_type == 'Safety Lock Trigger':
        # Normal veya Tripped durumu
        state = random.choice(['Normal', 'TRIPPED (Emergency Stop)'])
        detail = f"Lock: {state}"

    cursor.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)", 
                   (timestamp, e_type, detail))

db.commit()
print(f"Başarılı! {i+1} adet yeni formatta log eklendi.")
db.close()