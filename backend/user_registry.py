import os
import json
import re
from typing import List, Dict, Any
from pathlib import Path
import threading

class UserRegistry:
    def __init__(self, filepath: str = None):
        if filepath is None:
            # Save in the backend folder
            filepath = os.path.join(os.path.dirname(__file__), "registered_users.json")
        self.filepath = Path(filepath)
        self.lock = threading.Lock()
        with self.lock:
            self._load_users_unlocked()

    def _load_users_unlocked(self):
        if not self.filepath.exists():
            self.users = []
            self._save_users_unlocked()
        else:
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.users = json.load(f)
            except Exception as e:
                print(f"Error loading users from {self.filepath}: {e}")
                self.users = []

    def _save_users_unlocked(self):
        try:
            # Ensure parent directory exists
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            print(f"Error saving users to {self.filepath}: {e}")

    def get_users(self) -> List[Dict[str, Any]]:
        with self.lock:
            self._load_users_unlocked()
            return list(self.users)

    def add_user(self, email: str, name: str) -> bool:
        email = email.strip().lower()
        name = name.strip()
        
        # Simple email regex validation
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            return False

        with self.lock:
            # Avoid duplicate emails
            for u in self.users:
                if u["email"] == email:
                    return False
            
            from datetime import datetime
            created_at = datetime.now().isoformat()
            self.users.append({
                "email": email,
                "name": name,
                "created_at": created_at
            })
            self._save_users_unlocked()
            return True

    def remove_user(self, email: str) -> bool:
        email = email.strip().lower()
        with self.lock:
            original_len = len(self.users)
            self.users = [u for u in self.users if u["email"] != email]
            if len(self.users) < original_len:
                self._save_users_unlocked()
                return True
            return False
