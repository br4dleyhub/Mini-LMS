from flask import Flask, request, jsonify
import json
import os
import bcrypt

app = Flask(__name__)

@app.route("/")
def home():
    return "Mini-LMS server is running"

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return{}

    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    users = load_users()

    if username in users:
        return jsonify({"error": "user already exists"}), 400

    users[username] = {
        "password": password,
        "role": role
    }

    hashed_password = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    )

    users[username] = {
        "password": hashed_password.decode(),
        "role": role
    }

    save_users(users)
    return jsonify({"message": "user registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    users = load_users()

    if username not in users:
        return jsonify({"error": "Invalid credentials"}), 401

    stored_hash = users[username]["password"].encode()

    if not bcrypt.checkpw(password.encode(), stored_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful"}), 200


if __name__ == "__main__":
    app.run(debug=True)
