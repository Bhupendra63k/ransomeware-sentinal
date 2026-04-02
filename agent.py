"""
RansomSentinel — Agent
agent.py | File system monitor with heartbeat
"""

import time
import threading
import platform
import socket
import requests
from watchdog.observers import Observer
from monitor import RansomwareHandler
from config import DEVICE_NAME, SERVER_URL, WATCH_PATH, HEARTBEAT_INTERVAL

# ─── Heartbeat Thread ───
def heartbeat_loop():
    """Send periodic heartbeat to keep device marked online."""
    heartbeat_url = SERVER_URL.replace("/report", "/heartbeat")
    while True:
        try:
            requests.post(heartbeat_url, json={
                "device": DEVICE_NAME,
                "ip": get_local_ip(),
                "os": platform.system() + " " + platform.release()
            }, timeout=5)
            print(f"💓 Heartbeat sent from {DEVICE_NAME}")
        except Exception as e:
            print(f"⚠️ Heartbeat failed: {e}")
        time.sleep(HEARTBEAT_INTERVAL)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def send_alert_with_meta(file_path, reason):
    """Send an alert with enriched metadata."""
    data = {
        "device": DEVICE_NAME,
        "ip": get_local_ip(),
        "os": platform.system() + " " + platform.release(),
        "alerts": [{
            "time": time.strftime("%H:%M:%S"),
            "alert": reason,
            "file": file_path,
            "severity": infer_severity(reason)
        }]
    }
    try:
        requests.post(SERVER_URL, json=data, timeout=5)
        print(f"📡 Alert sent: {reason}")
    except:
        print("⚠️ Server not reachable")


def infer_severity(reason):
    t = reason.lower()
    if any(k in t for k in ["ransomware", "malware", "virustotal"]):
        return "high"
    if any(k in t for k in ["entropy", "suspicious", "extension"]):
        return "medium"
    return "low"


# ─── Main ───
if __name__ == "__main__":
    print(f"🛡 RansomSentinel Agent starting...")
    print(f"   Device: {DEVICE_NAME}")
    print(f"   Server: {SERVER_URL}")
    print(f"   Watching: {WATCH_PATH}")

    # Start heartbeat thread
    hb = threading.Thread(target=heartbeat_loop, daemon=True)
    hb.start()

    # Start file watcher
    handler = RansomwareHandler(send_alert_with_meta)
    observer = Observer()
    observer.schedule(handler, path=WATCH_PATH, recursive=True)
    observer.start()

    print("✅ Agent running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()