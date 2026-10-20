"""Исходная (уязвимая) версия API до исправлений по результатам SAST/DAST.
Хранится только для отчёта, в CI не сканируется."""
import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key-123"
DB_PATH = os.environ.get("DB_PATH", "users.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users ("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)")


@app.get("/api/users")
def list_users():
    name = request.args.get("name", "")
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'"
    try:
        rows = db().execute(query).fetchall()
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500
    return jsonify([dict(r) for r in rows])


@app.post("/api/users")
def create_user():
    data = request.get_json(force=True)
    with db() as conn:
        cur = conn.execute(
            f"INSERT INTO users (name, email) VALUES ('{data['name']}', '{data['email']}')"
        )
    return jsonify({"id": cur.lastrowid, **data}), 201


@app.delete("/api/users/<user_id>")
def delete_user(user_id):
    with db() as conn:
        conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    return jsonify({"deleted": user_id})


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
