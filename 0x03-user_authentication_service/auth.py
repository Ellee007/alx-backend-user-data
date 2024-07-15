#!/usr/bin/env python3
"""
Auth module
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """ Hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """ Generate UUID
    """
    from uuid import uuid4
    return str(uuid4())


def _generate_session_id() -> str:
    """ Generate session id
    """
    from uuid import uuid4
    return str(uuid4())


class Auth:
    """ Auth class
    """

    def __init__(self):
        """ Init
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Register a new user
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """ Validate login
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'), user._password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """ Create session
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_session_id()
            self._db.update_user(user, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """ Get user from session id
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None
