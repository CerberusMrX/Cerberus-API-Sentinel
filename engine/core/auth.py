import requests
from enum import Enum
from typing import Dict, Optional

class AuthType(Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"

class Authenticator:
    def __init__(self, auth_type: AuthType = AuthType.NONE, credentials: Dict = None):
        self.auth_type = auth_type
        self.credentials = credentials or {}

    def authenticate(self, session: requests.Session):
        """
        Applies authentication headers to the session.
        """
        if self.auth_type == AuthType.BASIC:
            username = self.credentials.get("username")
            password = self.credentials.get("password")
            if username and password:
                session.auth = (username, password)
        
        elif self.auth_type == AuthType.BEARER:
            token = self.credentials.get("token")
            if token:
                session.headers.update({"Authorization": f"Bearer {token}"})
        
        elif self.auth_type == AuthType.API_KEY:
            key_name = self.credentials.get("key_name", "X-API-Key")
            key_value = self.credentials.get("key_value")
            if key_value:
                session.headers.update({key_name: key_value})
