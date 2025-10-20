# analyzer.py
import re
from datetime import datetime
import sqlite3
import os

DB_PATH = "events.db"

# Простейшая функция для создания БД и таблицы, если ещё нет
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        event_type TEXT,
        user TEXT,
        ip TEXT,
        message TEXT
    )
    """)
    conn.commit()
    conn.close()

# Парсер одной строки лога -> dict (или None)
def parse_line(line):
    line = line.strip()
    if not line:
        return None

    # Попробуем извлечь стандартный префикс времени: YYYY-MM-DD HH:MM:SS
    ts_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$', line)
    if ts_match:
        timestamp = ts_match.group(1)
        rest = ts_match.group(2)
    else:
        timestamp = None
        rest = line

    level = None
    if rest.startswith("ERROR"):
        level = "ERROR"
    elif rest.startswith("WARNING"):
        level = "WARNING"
    elif "INFO" in rest.split()[0:1]:
        level = "INFO"

    # Detect login: "User 'admin' logged in from 192.168.0.10"
    m_login = re.search(r"User\s+'?\"?([A-Za-z0-9_\-@\.]+)'?\"?\s+logged in(?: from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))?", rest, re.IGNORECASE)
    if m_login:
        return {
            "timestamp": timestamp,
            "level": level or "INFO",
            "event_type": "login",
            "user": m_login.group(1),
            "ip": m_login.group(2) or None,
            "message": rest
        }

    # logout: "User 'admin' logged out"
    m_logout = re.search(r"User\s+'?\"?([A-Za-z0-9_\-@\.]+)'?\"?\s+logged out", rest, re.IGNORECASE)
    if m_logout:
        return {
            "timestamp": timestamp,
            "level": level or "INFO",
            "event_type": "logout",
            "user": m_logout.group(1),
            "ip": None,
            "message": rest
        }

    # failed login: "Failed login attempt from 192.168.0.11"
    m_failed = re.search(r"Failed login attempt(?: for user\s+'?\"?([A-Za-z0-9_\-@\.]+)'?\"?)?\s+from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", rest, re.IGNORECASE)
    if m_failed:
        return {
            "timestamp": timestamp,
            "level": "WARNING",
            "event_type": "failed_login",
            "user": m_failed.group(1) or None,
            "ip": m_failed.group(2),
            "message": rest
        }

    # Other ERROR or WARNING lines
    if "ERROR" in rest or "WARNING" in rest:
        return {
            "timestamp": timestamp,
            "level": "ERROR" if "ERROR" in rest else "WARNING",
            "event_type": "error" if "ERROR" in rest else "warning",
            "user": None,
            "ip": None,
            "message": rest
        }

    # Если строка не подошла под шаблоны — игнорируем (или можно сохранять как 'other')
    return None

# Разбор всего файла и вставка в БД
def analyze_and_store(file_path):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    inserted = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                cur.execute("""
                INSERT INTO events (timestamp, level, event_type, user, ip, message)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (ev["timestamp"], ev["level"], ev["event_type"], ev["user"], ev["ip"], ev["message"]))
                inserted += 1

    conn.commit()
    conn.close()
    return inserted

# Утилиты для получения данных (вызываются из Flask)
def get_events(limit=100, event_type=None):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if event_type:
        cur.execute("SELECT id, timestamp, level, event_type, user, ip, message FROM events WHERE event_type=? ORDER BY id DESC LIMIT ?", (event_type, limit))
    else:
        cur.execute("SELECT id, timestamp, level, event_type, user, ip, message FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    cols = ["id","timestamp","level","event_type","user","ip","message"]
    return [dict(zip(cols, r)) for r in rows]

def get_suspicious_ips(threshold=3):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    SELECT ip, COUNT(*) as cnt
    FROM events
    WHERE event_type='failed_login' AND ip IS NOT NULL
    GROUP BY ip
    HAVING cnt >= ?
    ORDER BY cnt DESC
    """, (threshold,))
    rows = cur.fetchall()
    conn.close()
    return [{"ip": r[0], "count": r[1]} for r in rows]
