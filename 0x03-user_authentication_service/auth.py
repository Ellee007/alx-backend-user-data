#!/usr/bin/env python3
""" Function that hashes password
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """ Hashes a password
    Return: hashed_password bytes
    """
    encoded_password = password.encode()
    return bcrypt.hashpw(encoded_password, bcrypt.gensalt())


def _generate_uuid() -> str:
    """ Generates and returns a new UUID
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """ class contructor
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Method to register user
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except Exception as err:
            pass
        if user:
            raise ValueError(f'User {email} already exists')
        else:
            hashed_password = _hash_password(password)
            registered_user = self._db.add_user(
                email=email, hashed_password=hashed_password)
            return registered_user

    def valid_login(self, email: str, password: str) -> bool:
        """ Credentials validation
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except Exception:
            return False
        if user:
            return bcrypt.checkpw(password.encode(), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Creates a session and returns a session ID
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except Exception:
            pass
        if user:
            session_id = str(uuid4())
            user.session_id = session_id
            return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """ Find user by session_id
        """
        if not session_id:
            return None

        user = None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except Exception:
            return None
        return user

    def destroy_session(self, user_id: int):
        """ Destroys session of a given user
        """
        user = None
        try:
            user = self._db.find_user_by(id=user_id)
        except Exception:
            pass
        if user:
            user.session_id = None

    def get_reset_password_token(self, email: str) -> str:
        """ Generate reset password token
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except Exception:
            raise ValueError
        if user:
            reset_token = _generate_uuid()
            user.reset_token = reset_token
            return reset_token

    def update_password(self, reset_token: str, password: str):
        """ Update password method
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except Exception:
            raise ValueError
        if user:
            password_hash = _hash_password(password)
            user.hashed_password = password_hash
            user.reset_token = None
