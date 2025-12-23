from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
import bcrypt
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

@app.route("/")
def home():
    return "Mini-LMS server is running"

USERS_FILE = "users.json"

def get_db_connection():
    return sqlite3.connect(DB_PATH)


@app.route("/register", methods=["POST"])
def register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    hashed_password = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, role)
        )

        conn.commit()
        conn.close()

        log_event(f"REGISTER success for username: {username}")
        return jsonify({"message": "User registered successfully"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400

@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/login", methods=["POST"])
def login():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        log_event(f"LOGIN failed for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    stored_hash = row[0].encode()

    if not bcrypt.checkpw(password.encode(), stored_hash):
        log_event(f"LOGIN failed for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    log_event(f"LOGIN success for username: {username}")
    return jsonify({"message": "Login successful"}), 200

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/privacy", methods=["GET"])
def privacy_notice():
    return jsonify({
        "notice": "This system stores usernames and hashed passwords for educational purposes only."
    }), 200

def log_event(event):
    timestamp = datetime.now(timezone.utc).isoformat()
    with open("auth.log", "a") as log:
        log.write(f"{timestamp} - {event}\n")

@app.route("/users", methods=["GET"])
def list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    rows = cursor.fetchall()
    conn.close()

    return jsonify(rows), 200

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
