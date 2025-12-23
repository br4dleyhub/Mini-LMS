import requests

url = "http://127.0.0.1:5000/login"

data = {
    "username": "Nicko",
    "password": "8520"
}

response = requests.post(url, json=data)
print(response.status_code)
print(response.json())