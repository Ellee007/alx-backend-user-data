#!/usr/bin/env python3
""" Handles all routes for the Session authentication
"""
from api.v1.views import app_views
from flask import request, jsonify
from models.user import User
import os


@app_views.route('/auth_session/login', strict_slashes=False, methods=['POST'])
def login():
    """ Login view
    Returns:
        An authentication User object with an active session
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None:
        return jsonify({"error": "email missing"}), 400
    if password is None:
        return jsonify({"error": "password missing"}), 400

    user = User.search({"email": email})
    if len(user) == 0:
        return jsonify({"error", "no user found for this email"}), 404
    user = user[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    session_id = auth.create_session(user.id)
    session = os.getenv('SESSION_NAME')
    user_json = jsonify(user.to_json())
    user_json.set_cookies(session, session_id)

    return user_json
