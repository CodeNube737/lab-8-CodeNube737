#sensor_client.py
# A simple client to test the sensor data API endpoint.
# run in terminal to retrieve log.
import requests
import os
import json
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

response = requests.post(url, headers=headers, data=json.dumps(data))
print("Status:", response.status_code)
print("Response:", response.json())
