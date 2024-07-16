#!/usr/bin/env python3
""" Basic flask app
"""
from flask import Flask, jsonify, request, make_response, abort
from flask import redirect
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route("/")
def index():
    """ Home route
    """
    payload = {"message": "Bienvenue"}
    return jsonify(payload)


@app.route("/users", methods=['POST'])
def users():
    """ User registration
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(email, password)
        user = None
        try:
            user = AUTH.register_user(email, password)
        except ValueError:
            return jsonify({"message": "email already registered"}), 400
        except Exception as err:
            pass
        if user:
            payload = {
                "email": email,
                "message": "user created"
            }
            return jsonify(payload)


@app.route('/sessions', methods=['POST'])
def login():
    """ Login route
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if AUTH.valid_login(email, password):
            session_id = None
            session_id = AUTH.create_session(email)
            payload = {
                "email": email,
                "message": "logged in"
            }
            response = make_response(payload)
            response.set_cookie("session_id", session_id)
            return response
        else:
            abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout():
    """ Logout route
    """
    if request.method == "DELETE":
        session_id = request.cookies.get('session_id')
        if session_id:
            user = AUTH.get_user_from_session_id(session_id)
            if user:
                AUTH.destroy_session(user.id)
                return redirect("/")
            else:
                abort(403)
        else:
            abort(403)


@app.route("/profile")
def profile():
    """ Profile route
    """
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email}), 200
        else:
            abort(403)
    else:
        abort(403)


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """ Reset password route
    """
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            abort(403)
        user = None
        try:
            user = AUTH._db.find_user_by(email=email)
        except Exception:
            abort(403)
        if user:
            reset_token = AUTH.get_reset_password_token(email)
            payload = {
                "email": email,
                "reset_token": reset_token
            }
            return jsonify(payload), 200
        else:
            abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """ Update password route
    """
    if request.method == "PUT":
        email = request.form.get("email")
        reset_token = request.form.get("reset_token")
        new_password = request.form.get("new_password")
        try:
            AUTH.update_password(reset_token, new_password)
        except ValueError:
            abort(403)
        payload = {"email": email, "message": "Password updated"}
        return jsonify(payload), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
