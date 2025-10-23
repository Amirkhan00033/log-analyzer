# app.py
import os
import sqlite3
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, url_for, session, flash

DB_PATH = "site_events.db"
UPLOAD_FOLDER = "uploads"

app = Flask(__name__)
app.secret_key = "supersecretkey"  # поменяй на свой секрет
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------------
# DB helpers
# -------------------------
def get_db():
    if "_db" not in g:
        g._db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g._db.row_factory = sqlite3.Row
    return g._db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("_db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    # таблица пользователей
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # таблица событий
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP,
            ip TEXT,
            path TEXT,
            event_type TEXT,
            username TEXT,
            user_agent TEXT,
            message TEXT
        )
    """)
    db.commit()

def ensure_admin():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            ("admin", "admin123", 1)
        )
        db.commit()

# -------------------------
# Logging utility
# -------------------------
def log_event(event_type, username=None, message=None):
    db = get_db()
    cur = db.cursor()
    ip = request.remote_addr or request.environ.get("HTTP_X_FORWARDED_FOR", "")
    ua = request.headers.get("User-Agent", "")
    cur.execute("""
        INSERT INTO events (ts, ip, path, event_type, username, user_agent, message)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (datetime.utcnow(), ip, request.path, event_type, username, ua, message))
    db.commit()

@app.before_request
def before_all():
    init_db()
    ensure_admin()
    if request.path.startswith("/static") or request.path.startswith("/favicon.ico"):
        return
    if request.method == "GET":
        user = session.get("username")
        log_event("view", username=user)

# -------------------------
# Auth routes
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT username, password FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or password != row["password"]:
            log_event("failed_login", username=username, message="bad login")
            flash("Неверный логин/пароль")
            return redirect(url_for("login"))
        session["username"] = username
        log_event("login", username=username, message="successful login")
        flash("Вход выполнен")
        return redirect(url_for("admin_dashboard"))
    return render_template("login.html", user=session.get("username"))

@app.route("/logout")
def logout():
    user = session.pop("username", None)
    log_event("logout", username=user, message="user logged out")
    flash("Выход выполнен")
    return redirect(url_for("login"))

def require_admin():
    user = session.get("username")
    if not user:
        return False
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT is_admin FROM users WHERE username=?", (user,))
    r = cur.fetchone()
    return r and r["is_admin"] == 1

# -------------------------
# Public routes
# -------------------------
@app.route("/")
def index():
    # Главная страница сразу открывает сайт колледжа
    return redirect(url_for("colleage"))

@app.route("/colleage")
def colleage():
    log_event("view_colleage", username=session.get("username"), message="visited colleage page")
    return render_template("colleage.html", user=session.get("username"))

# -------------------------
# Admin dashboard
# -------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if not require_admin():
        flash("Требуется админ-доступ")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()

    # изменить логин/пароль админа
    if request.method == "POST":
        new_username = request.form.get("new_username", "").strip()
        new_password = request.form.get("new_password", "").strip()
        if new_username:
            cur.execute("UPDATE users SET username=? WHERE is_admin=1", (new_username,))
        if new_password:
            cur.execute("UPDATE users SET password=? WHERE is_admin=1", (new_password,))
        db.commit()
        flash("Логин/пароль обновлены!")

    # последние 50 событий
    cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 50")
    events = cur.fetchall()
    return render_template("admin.html", events=events, user=session.get("username"))

# -------------------------
# IP lookup
# -------------------------
@app.route("/ip/<ipaddr>")
def ip_lookup(ipaddr):
    if not require_admin():
        flash("Требуется админ-доступ")
        return redirect(url_for("login"))
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM events WHERE ip LIKE ? ORDER BY ts DESC LIMIT 50", (f"%{ipaddr}%",))
    rows = cur.fetchall()
    return render_template("ip.html", events=rows, ip=ipaddr, user=session.get("username"))

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
        ensure_admin()
    app.run(debug=True, host="0.0.0.0", port=5000)
