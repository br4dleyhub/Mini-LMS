from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone, timedelta  # Combined imports
import bcrypt
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)

# Fixed: Initialized with a proper datetime object instead of the class name
login_attempts = {}

MAX_ATTEMPTS = 5
BLOCK_TIME = timedelta(minutes=10)

def is_blocked(username):
    attempt = login_attempts.get(username)
    if not attempt:
        return False
    if attempt["count"] < MAX_ATTEMPTS:
        return False
    # Fixed: Use timezone-aware comparison
    if datetime.now(timezone.utc) - attempt["last_attempt"] > BLOCK_TIME:
        del login_attempts[username]
        return False
    return True

def record_failed_attempt(username):
    if username not in login_attempts:
        login_attempts[username] = {
            "count": 1,
            "last_attempt": datetime.now(timezone.utc)
        }
    else:
        login_attempts[username]["count"] += 1
        login_attempts[username]["last_attempt"] = datetime.now(timezone.utc)

def reset_attempts(username):
    if username in login_attempts:
        del login_attempts[username]

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

def get_db_connection():
    return sqlite3.connect(DB_PATH)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() if request.is_json else request.form
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
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
    # Fix 1: Get data FIRST so 'username' exists for the is_blocked check
    data = request.get_json() if request.is_json else request.form
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    # Now we can safely check if they are blocked
    if is_blocked(username):
        log_event(f"LOGIN blocked for username: {username}")
        return jsonify({"error": "Too many failed attempts. Try later."}), 429

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        record_failed_attempt(username)
        log_event(f"LOGIN failed for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    stored_hash = row[0].encode()

    if not bcrypt.checkpw(password.encode(), stored_hash):
        # Fix 2: Added failed attempt recording here too
        record_failed_attempt(username)
        log_event(f"LOGIN failed for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    log_event(f"LOGIN success for username: {username}")
    reset_attempts(username)
    return jsonify({"message": "Login successful"}), 200

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/privacy", methods=["GET"])
def privacy_notice():
    return jsonify({"notice": "This system stores usernames and hashed passwords for educational purposes only."}), 200

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