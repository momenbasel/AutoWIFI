import json
from pathlib import Path


DEFAULT_CONFIG = {
    "interface": "wlan0",
    "scan_duration": 30,
    "deauth_count": 15,
    "deauth_delay": 0.1,
    "deauth_continuous": False,
    "handshake_timeout": 180,
    "default_wordlist": "/usr/share/wordlists/rockyou.txt",
    "crack_backend": "aircrack",
    "output_dir": "~/.autowifi/output",
    "session_dir": "~/.autowifi/sessions",
    "report_dir": "~/.autowifi/reports",
    "hashcat_workload": 3,
    "wps_timeout": 600,
    "wps_pixie_dust": True,
    "channel_hop": True,
    "save_pcap": True,
    "mac_randomize": False,
    "band": "abg",
    "stealth_mode": False,
    "auto_crack": True,
    "scan_interval": 1,
}


class Config:
    _instance = None
    _config_path = Path.home() / ".autowifi" / "config.json"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._data = dict(DEFAULT_CONFIG)
            cls._instance._loaded = False
        return cls._instance

    def load(self):
        if self._loaded:
            return
        if self._config_path.exists():
            with open(self._config_path) as f:
                saved = json.load(f)
                self._data.update(saved)
        self._loaded = True
        self._ensure_dirs()

    def save(self):
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value

    def _ensure_dirs(self):
        for key in ("output_dir", "session_dir", "report_dir"):
            path = Path(self._data[key]).expanduser()
            path.mkdir(parents=True, exist_ok=True)
            self._data[key] = str(path)

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value

    @property
    def all(self):
        return dict(self._data)
