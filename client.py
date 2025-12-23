import requests

url = "http://127.0.0.1:5000/register"

data = {
    "username": "alice",
    "password": "1234",
    "role": "admin"
}

response = requests.post(url, json=data)
print(response.status_code)
print(response.json())