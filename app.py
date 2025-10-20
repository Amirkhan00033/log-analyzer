# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from analyzer import analyze_and_store, get_events, get_suspicious_ips, init_db

UPLOAD_FOLDER = "uploads"
ALLOWED_EXT = set(['txt','log','out','log.txt','log.1'])  # доп. фильтр, простой

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "change_this_to_more_secure_key"

def allowed_file(filename):
    if "." not in filename:
        return True  # разрешаем файлы без расширения (текстовые)
    ext = filename.rsplit(".",1)[1].lower()
    return ext in ALLOWED_EXT or ext == "txt" or ext == "log"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    if 'logfile' not in request.files:
        flash("Нет файла в запросе")
        return redirect(url_for('index'))
    file = request.files['logfile']
    if file.filename == "":
        flash("Файл не выбран")
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)

    # Анализируем и сохраняем в БД
    inserted = analyze_and_store(save_path)
    flash(f"Файл загружен и проанализирован. Добавлено событий: {inserted}")
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
def dashboard():
    # фильтр по типу ?type=login
    event_type = request.args.get("type")
    limit = request.args.get("limit", 200, type=int)
    events = get_events(limit=limit, event_type=event_type)
    suspicious = get_suspicious_ips(threshold=3)
    return render_template("dashboard.html", events=events, suspicious=suspicious, selected_type=event_type)

if __name__ == "__main__":
    app.run(debug=True)
