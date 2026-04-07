import json
import os
import time
import uuid
import shutil
from pathlib import Path
from dataclasses import asdict
from datetime import datetime


class Session:
    def __init__(self, session_dir):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._current_id = None
        self._data = {}

    def create(self, target_bssid, target_essid, attack_type):
        self._current_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        session_path = self.session_dir / self._current_id
        session_path.mkdir(parents=True, exist_ok=True)

        self._data = {
            "id": self._current_id,
            "created": time.time(),
            "updated": time.time(),
            "target_bssid": target_bssid,
            "target_essid": target_essid,
            "attack_type": attack_type,
            "status": "active",
            "results": [],
            "files": [],
            "notes": [],
        }

        self._save()
        return self._current_id

    def update(self, **kwargs):
        self._data.update(kwargs)
        self._data["updated"] = time.time()
        self._save()

    def add_result(self, result):
        if hasattr(result, "__dict__"):
            result_data = {k: v for k, v in result.__dict__.items() if not k.startswith("_")}
        elif hasattr(result, "_asdict"):
            result_data = result._asdict()
        else:
            result_data = dict(result) if isinstance(result, dict) else {"value": str(result)}

        self._data.setdefault("results", []).append(result_data)
        self._data["updated"] = time.time()
        self._save()

    def add_file(self, filepath, description=""):
        session_path = self.session_dir / self._current_id
        if os.path.exists(filepath):
            dest = session_path / os.path.basename(filepath)
            shutil.copy2(filepath, dest)
            self._data.setdefault("files", []).append({
                "path": str(dest),
                "original": filepath,
                "description": description,
                "added": time.time(),
            })
            self._save()

    def complete(self, key=""):
        self._data["status"] = "completed"
        self._data["key"] = key
        self._data["completed"] = time.time()
        self._data["updated"] = time.time()
        self._save()

    def fail(self, reason=""):
        self._data["status"] = "failed"
        self._data["failure_reason"] = reason
        self._data["updated"] = time.time()
        self._save()

    def load(self, session_id):
        meta_file = self.session_dir / session_id / "session.json"
        if not meta_file.exists():
            return None
        with open(meta_file) as f:
            self._data = json.load(f)
        self._current_id = session_id
        return self._data

    def list_sessions(self):
        sessions = []
        for entry in sorted(self.session_dir.iterdir(), reverse=True):
            if entry.is_dir():
                meta_file = entry / "session.json"
                if meta_file.exists():
                    with open(meta_file) as f:
                        data = json.load(f)
                    sessions.append(data)
        return sessions

    def delete(self, session_id):
        session_path = self.session_dir / session_id
        if session_path.exists():
            shutil.rmtree(session_path)
            return True
        return False

    def _save(self):
        if not self._current_id:
            return
        session_path = self.session_dir / self._current_id
        session_path.mkdir(parents=True, exist_ok=True)
        meta_file = session_path / "session.json"
        with open(meta_file, "w") as f:
            json.dump(self._data, f, indent=2, default=str)

    @property
    def current(self):
        return dict(self._data) if self._data else None

    @property
    def session_path(self):
        if self._current_id:
            return str(self.session_dir / self._current_id)
        return None
