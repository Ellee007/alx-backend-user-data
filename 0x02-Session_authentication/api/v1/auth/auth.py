#!/usr/bin/env python3
""" Authentication module
"""
from flask import request
from typing import List, TypeVar
import os


class Auth:
    """ Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Checks if a given path requires authentication """
        if path is None:
            return True

        if not path.endswith('/'):
            path = path + '/'
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path in excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """ Responsible for authorization """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ current user """
        return None

    def session_cookie(self, request=None):
        """ Returns a cookie value from a request
        """
        if request is None:
            return None
        cookie_name = os.getenv("SESSION_NAME")
        if cookie_name:
            return request.cookies.get(cookie_name)
