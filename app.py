#app.py
from __future__ import annotations
from functools import wraps
from typing import Optional, Tuple, Union
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask.typing import ResponseReturnValue
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin.firestore import DocumentReference
import os
import requests

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY")

"""
# A dummy user for the login... i replaced every other instance of 'username' with 'email', so this is no longer needed.
dummy_user = {
    "username": "student",
    "password": "secret"
}
"""

# Initialize Firestore
if not firebase_admin._apps:
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", "serviceAccountKey.json")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()

def get_current_user():
    """Return the currently logged-in email (or None).

    Uses session data set during `/login`. This keeps all login checks
    consistent in one place.
    """
    if not session.get("logged_in"):
        return None
    return session.get("email")


def get_user_or_401():
    """Return the current API user (uid) or an Unauthorized response."""
    # Try to get JWT from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized: Missing or invalid Authorization header"}), 401
    token = auth_header.split(" ", 1)[1]
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception as e:
        return jsonify({"error": f"Unauthorized: {str(e)}"}), 401


def get_profile_doc_ref(email: str):
    """Get the Firestore document reference for a user's profile."""
    return db.collection("profiles").document(email)


def get_profile_data(email: str):
    """Fetch a user's profile from Firestore, returning an empty dict if missing."""
    doc = get_profile_doc_ref(email).get()
    return doc.to_dict() if doc.exists else {}


def validate_profile_data(first_name: str, last_name: str, student_id: str):
    """Validate that required profile fields are present and well-formed."""
    if not first_name or not last_name or not student_id:
        return "All fields are required."
    return None


def normalize_profile_data(first_name: str, last_name: str, student_id: str):
    """Normalize profile field values (strip whitespace, stringify student_id)."""
    return {
        "first_name": first_name.strip() if first_name else "",
        "last_name": last_name.strip() if last_name else "",
        "student_id": str(student_id).strip() if student_id else ""
    }


def require_json_content_type():
    """Ensure the request is JSON; returns an error response tuple if not."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


def set_profile(email: str, profile_data: dict[str, str], *, merge: bool):
    """Persist profile data to Firestore.

    Args:
        email: Profile owner.
        profile_data: Data to write.
        merge: When True, merges into existing document (partial update).
    """
    get_profile_doc_ref(email).set(profile_data, merge=merge)
    return None
    
def set_sensor_value(sensor_id: str, value: float, timestamp: str):
    db.collection("sensors").document(sensor_id).set({
        "value": value,
        "timestamp": timestamp
    })
    return None

def get_sensor_value(sensor_id: str):
    doc = db.collection("sensors").document(sensor_id).get()
    if doc.exists:
        return doc.to_dict()
    return {"value": None, "timestamp": None}

# --- Web Routes ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Signup page: create a new user and profile."""
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    if password != confirm_password:
        return render_template("signup.html", error="Passwords do not match")

    try:
        user = auth.create_user(email=email, password=password)
        db.collection("profiles").document(user.uid).set({
            "email": email,
            "role": "user"
        })
        return redirect(url_for("login"))
    except Exception as e:
        return render_template("signup.html", error=f"Signup failed: {str(e)}")


@app.route("/signup", methods=["POST"])
def api_signup():
    """API endpoint to create a user and profile."""
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    try:
        user = auth.create_user(email=email, password=password)
        db.collection("profiles").document(user.uid).set({
            "email": email,
            "role": "user"
        })
        return jsonify({"message": "Signup successful"}), 200
    except Exception as e:
        return jsonify({"error": f"Signup failed: {str(e)}"}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    """API endpoint to log in and return JWT."""
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    res = requests.post(url, json=payload)
    if res.status_code == 200:
        return jsonify({"token": res.json()["idToken"]}), 200
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/")
def home():
    """Home page. Redirects to login if no active session. Displays user profile info and sensor value if logged in."""
    current_user = get_current_user()
    if current_user:
        profile_data = get_profile_data(current_user)
        sensor_data = get_sensor_value("sensor-001")
        return render_template("dashboard.html", username=current_user, profile=profile_data, sensor=sensor_data)
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page using Firebase REST API for authentication."""
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email")  # Email field
    password = request.form.get("password")

    if not email or not password:
        return render_template("login.html", error="Email and password required.")

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    res = requests.post(url, json=payload)
    if res.status_code == 200:
        session["logged_in"] = True
        session["email"] = email
        return redirect(url_for("home"))
    return render_template("login.html", error="Invalid credentials. Try again.")


@app.route("/logout")
def logout():
    """Clear the session and return to login."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    """HTML form to create/update the current user's profile."""
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for("login"))

    if request.method == "GET":
        profile_data = get_profile_data(current_user)
        return render_template("profile.html", profile=profile_data, error=None)

    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")
    student_id = request.form.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        profile_data = {"first_name": first_name, "last_name": last_name, "student_id": student_id}
        return render_template("profile.html", profile=profile_data, error=error)

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(current_user, normalized, merge=False)
    return redirect(url_for("home"))


# --- API Routes ---

@app.get("/api/profile")
def api_get_profile():
    """Return the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    email = user_or_response
    profile_data = get_profile_data(email)
    return jsonify({"email": email, "profile": profile_data}), 200


@app.post("/api/profile")
def api_create_profile():
    """Create/replace the current user's profile from a JSON body."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    email = user_or_response
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")
    student_id = data.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        return jsonify({"error": error}), 400

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(email, normalized, merge=False)
    return jsonify({"message": "Profile saved successfully", "profile": normalized}), 200


@app.put("/api/profile")
def api_update_profile():
    """Update the current user's profile from a JSON body."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    email = user_or_response
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Request body cannot be empty"}), 400

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    student_id = data.get("student_id")

    # Prepare the update data (only include provided fields)
    update_data = {}
    if first_name is not None:
        update_data["first_name"] = first_name.strip() if first_name else ""
    if last_name is not None:
        update_data["last_name"] = last_name.strip() if last_name else ""
    if student_id is not None:
        update_data["student_id"] = str(student_id).strip() if student_id else ""

    if not update_data:
        return jsonify({"error": "No updatable fields provided"}), 400

    # Merge update into existing document (or create if missing).
    set_profile(email, update_data, merge=True)

    updated_profile = get_profile_data(email)
    return jsonify({"message": "Profile updated successfully", "profile": updated_profile}), 200


@app.delete("/api/profile")
def api_delete_profile():
    """Delete the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    email = user_or_response
    get_profile_doc_ref(email).delete()
    return jsonify({"message": "Profile deleted successfully"}), 200


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected_key = os.environ.get("SENSOR_API_KEY")
        provided_key = request.headers.get("X-API-Key")
        if not provided_key or provided_key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route("/api/sensor_data", methods=["POST"])
@require_api_key
def sensor_data():
    data = request.get_json(silent=True) or {}
    sensor_id = data.get("sensor_id", "sensor-001")
    value = data.get("value")
    timestamp = data.get("timestamp")
    set_sensor_value(sensor_id, value, timestamp)
    return jsonify({"received": data}), 200

@app.route("/api/sensor_value", methods=["GET"])
def api_get_sensor_value():
    sensor_id = request.args.get("sensor_id", "sensor-001")
    sensor_data = get_sensor_value(sensor_id)
    return jsonify(sensor_data), 200

#------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)