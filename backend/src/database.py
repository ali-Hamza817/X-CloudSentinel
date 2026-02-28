import sqlite3
import os
import json
from datetime import datetime

DB_PATH = "f:/Fullbright Scholarship/X-CloudSentinel/backend/data/X-CloudSentinel.db"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tables for scan history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT,
            sqi_score REAL,
            findings_count INTEGER,
            ai_classification TEXT,
            raw_data TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def log_scan(file_path, sqi_score, findings_count, ai_class, raw_findings):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scan_history (file_path, sqi_score, findings_count, ai_classification, raw_data)
        VALUES (?, ?, ?, ?, ?)
    ''', (file_path, sqi_score, findings_count, ai_class, json.dumps(raw_findings)))
    
    conn.commit()
    conn.close()

def get_history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "timestamp": row[1],
            "file_path": row[2],
            "sqi_score": row[3],
            "findings_count": row[4],
            "ai_classification": row[5]
        })
        
    conn.close()
    return history

if __name__ == "__main__":
    init_db()

