#sensor_client.py
# A simple client to test the sensor data API endpoint.
# run in terminal to retrieve log.

import requests
import os
import json
import getpass
# Load API key from .env or set directly
from dotenv import load_dotenv
load_dotenv()

url = "http://127.0.0.1:5000/api/sensor_data"
headers = {
    "Content-Type": "application/json",
    "X-API-Key": os.getenv("SENSOR_API_KEY")
}

# Prompt user for a float value with error checking
while True:
    try:
        value = float(input("Enter new sensor value (float): "))
        if not (0 <= value <= 1000):
            print("Value should be between 0 and 1000.")
            continue
        break
    except ValueError:
        print("Invalid input. Please enter a decimal number.")

import datetime
timestamp = datetime.datetime.now().isoformat()

data = {
    "sensor_id": "sensor-001",
    "value": value,
    "timestamp": timestamp
}
# Restore sensor POST request and output
response = requests.post(url, headers=headers, data=json.dumps(data))
print("Status:", response.status_code)
print("Response:", response.json())


# --- Profile update testing ---
print("\n--- Profile Update Testing ---")
profile_url = "http://127.0.0.1:5000/api/profile"

# Prompt for email and password, then log in to get JWT
email = input("Enter your email for profile update: ")
password = getpass.getpass("Enter your password: ")
login_url = "http://127.0.0.1:5000/api/login"
login_payload = {"email": email, "password": password}
login_response = requests.post(login_url, headers={"Content-Type": "application/json"}, data=json.dumps(login_payload))
if login_response.status_code == 200:
    token = login_response.json()["token"]
    print("Login successful. JWT token retrieved.")
else:
    print("Login failed:", login_response.json())
    token = None

if token:
    profile_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }

    # Example payloads
    payloads = [
        {"first_name": "mik", "last_name": "re", "student_id": "0123456789"},
        {"first_name": "a"*51, "last_name": "b", "student_id": "12345678"},  # Too long first_name
        {"first_name": "John", "last_name": "Doe", "student_id": "1234!@#$"},  # Invalid student_id
        {"first_name": "Jane", "last_name": "Smith", "student_id": "123456789", "extra_field": "should_fail"},  # Extra field
        {"first_name": "Alice", "last_name": "Smith", "student_id": "A1234567"},  # Valid payload
    ]

    for idx, payload in enumerate(payloads):
        print(f"\nPayload {idx+1}: {payload}")
        response = requests.put(profile_url, headers=profile_headers, data=json.dumps(payload))
        print("Status:", response.status_code)
        print("Response:", response.json())
