# RansomSentinel Agent Configuration

import os

# ─── Device Identity ───
DEVICE_NAME = os.environ.get("RS_DEVICE_NAME", "Linux-Device-1")

# ─── Server ───
SERVER_HOST = os.environ.get("RS_SERVER_HOST", "192.168.53.218")
SERVER_PORT = os.environ.get("RS_SERVER_PORT", "5000")
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}/report"

# ─── Watch Path ───
WATCH_PATH = os.environ.get("RS_WATCH_PATH", "/home")

# ─── Heartbeat ───
HEARTBEAT_INTERVAL = 30  # seconds

# ─── Detection Thresholds ───
THRESHOLD = 50
TIME_WINDOW = 60
RENAME_THRESHOLD = 10
ENTROPY_THRESHOLD = 7.0

# ─── VirusTotal ───
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "0c782169fe65c134d45abd27f0f7f37c8a66d58c8b769669cbccb5f474f895d0")
