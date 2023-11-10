#!/usr/bin/env python3
"""
Module for authentication using Session auth with expiration
"""

from .session_auth import SessionAuth
from models.user import User
from uuid import uuid4
from datetime import datetime, timedelta
import os

class SessionExpAuth(SessionAuth):
    """Session authentication with expiration
    """

    def __init__(self):
        """Initialize SessionExpAuth instance."""
        super().__init__()
        self.session_duration = int(os.getenv("SESSION_DURATION", 0))

    def create_session(self, user_id: str = None) -> str:
        """Create a Session ID with expiration date.

        Args:
            user_id (str, optional): User ID. Defaults to None.

        Returns:
            str: Session ID.
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        session_dict = {
            "user_id": user_id,
            "created_at": datetime.now()
        }

        self.user_id_by_session_id[session_id] = session_dict
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieve user_id for a given Session ID with expiration.

        Args:
            session_id (str, optional): Session ID. Defaults to None.

        Returns:
            str: User ID.
        """
        if session_id is None or session_id not in self.user_id_by_session_id:
            return None

        session_dict = self.user_id_by_session_id[session_id]

        if self.session_duration <= 0:
            return session_dict.get("user_id")

        if "created_at" not in session_dict:
            return None

        expiration_time = session_dict["created_at"] + timedelta(seconds=self.session_duration)

        if datetime.now() > expiration_time:
            return None

        return session_dict.get("user_id")