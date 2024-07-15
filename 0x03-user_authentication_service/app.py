#!/usr/bin/env python3
"""
App module
Create a Flask app that has a single GET route ("/") and use flask.jsonify to return a JSON payload of the form:
"""

from flask import Flask, jsonify, request
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """ GET /
    Return:
      - JSON payload
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """ POST /users
    Return:
      - JSON payload
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    return jsonify({"email": user.email, "message": "user created"})


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """ POST /sessions
    Return:
      - JSON payload
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.valid_login(email, password)
    except Exception:
        return jsonify({"message": "wrong email or password"}), 401
    session_id = AUTH.create_session(email)
    return jsonify({"email": email, "message": "logged in",
                    "session_id": session_id})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
