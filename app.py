import json
import os
USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r") as file:
        return json.load(file)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

def register_user():
    users = load_users()

    username = input("Username: ")

    if username in users:
        print("user already exists")
        return

    password = input("Password: ")
    role = input("Role (student/admin): ")

    users[username] = {
        "password": password,
        "role": role
    }

    save_users(users)
    print("User registered successfully")

def login_user():
    users = load_users()

    username = input("Username: ")
    password = input("Password: ")

    if username not in users:
        print("User not found")
        return None

    if users[username]["password"] != password:
        print("Incorrect password")
        return None

    print("Login successful")
    return username

def view_profile(username):
    users = load_users()
    user = users.get(username)

    print("\n--- Profile ---")
    print("Username:", username)
    print("Role:", user["role"])

def main():
    logged_in_user = None

    while True:
        if logged_in_user:
            print(f"\n--- Welcome, {logged_in_user} ! ---")
        print("\n--- Mini-LMS Menu ---")
        print("1. Register")
        print("2. Login")
        print("3. View Profile")
        print("4. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            logged_in_user = login_user()
        elif choice == "3":
            if logged_in_user:
                view_profile(logged_in_user)
            else:
                print("Please login first")
        elif choice == "4":
            break

if __name__ == "__main__":
    main()