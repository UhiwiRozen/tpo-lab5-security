"""API пользователей (Flask + SQLite) – исправленная версия после SAST/DAST."""
import os
import re
import secrets
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
# Секреты берутся из окружения, а не из кода (OWASP A02/A07)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
API_TOKEN = os.environ.get("API_TOKEN", "")
DB_PATH = os.environ.get("DB_PATH", "users.db")

NAME_RE = re.compile(r"^[\w .\-]{1,50}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users ("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                     "name TEXT NOT NULL, email TEXT NOT NULL UNIQUE)")


@app.after_request
def security_headers(resp):
    # Защитные заголовки (OWASP A05 Security Misconfiguration)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "method not allowed"}), 405


@app.errorhandler(Exception)
def internal_error(_):
    # Детали исключения не раскрываются клиенту
    return jsonify({"error": "internal server error"}), 500


@app.get("/api/users")
def list_users():
    name = request.args.get("name", "")
    if len(name) > 50:
        return jsonify({"error": "name filter too long"}), 400
    rows = get_db().execute(
        "SELECT id, name, email FROM users WHERE name LIKE ? ORDER BY id LIMIT 100",
        (f"%{name}%",),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/users")
def create_user():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body required"}), 400
    name, email = data.get("name"), data.get("email")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        return jsonify({"error": "invalid name"}), 400
    if not isinstance(email, str) or not EMAIL_RE.fullmatch(email):
        return jsonify({"error": "invalid email"}), 400
    db = get_db()
    try:
        cur = db.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "email already exists"}), 409
    return jsonify({"id": cur.lastrowid, "name": name, "email": email}), 201


@app.delete("/api/users/<int:user_id>")
def delete_user(user_id):
    # Удаление только с токеном (OWASP A01 Broken Access Control)
    token = request.headers.get("X-API-Key", "")
    if not API_TOKEN or not secrets.compare_digest(token, API_TOKEN):
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    cur = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    return jsonify({"deleted": user_id})


init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000,
            debug=os.environ.get("FLASK_DEBUG") == "1")
