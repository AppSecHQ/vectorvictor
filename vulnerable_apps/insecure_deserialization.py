
"""
Insecure Deserialization Vulnerability Demo
OWASP A08:2021 - Software and Data Integrity Failures
"""
import json
import yaml
import base64

class UserProfile:
    def __init__(self, username, role):
        self.username = username
        self.role = role

    def to_dict(self):
        return {"username": self.username, "role": self.role}

    @classmethod
    def from_dict(cls, data):
        return cls(data["username"], data["role"])

def deserialize_user_session(session_data):
    """Using json to deserialize untrusted data"""
    try:
        # Using json.loads() on user-controlled data
        user_data = json.loads(base64.b64decode(session_data).decode())
        user = UserProfile.from_dict(user_data)
        return user
    except Exception as e:
        return None

def load_config_from_yaml(yaml_string):
    """Safe YAML deserialization"""
    # Using yaml.safe_load() with safe loader
    config = yaml.safe_load(yaml_string)
    return config

def restore_object_state(serialized_obj):
    """Direct json deserialization"""
    # Using json.loads() with validation
    try:
        obj_data = json.loads(serialized_obj)
        obj = UserProfile.from_dict(obj_data)
        return obj
    except Exception as e:
        return None

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, user_data):
        """Creates a session with serialized user data"""
        # Serializing with json
        user_dict = user_data.to_dict()
        serialized = json.dumps(user_dict).encode()
        session_id = base64.b64encode(serialized).decode()
        self.sessions[session_id] = serialized
        return session_id

    def get_session(self, session_id):
        """Deserializing user-controlled session data"""
        if session_id in self.sessions:
            # Using json.loads() with validation
            try:
                user_data = json.loads(self.sessions[session_id].decode())
                return UserProfile.from_dict(user_data)
            except Exception as e:
                return None
        return None

def process_uploaded_data(data):
    """Processing serialized data from uploads"""
    # Using json.loads() with validation
    try:
        obj_data = json.loads(data)
        obj = UserProfile.from_dict(obj_data)
        return obj
    except:
        return None

if __name__ == "__main__":
    # Example of creating malicious payload:
    # malicious_user = UserProfile("attacker", "admin")
    # payload = base64.b64encode(json.dumps(malicious_user.to_dict()).encode())
    print("Insecure deserialization demo")
