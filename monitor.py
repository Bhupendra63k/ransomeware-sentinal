from watchdog.events import FileSystemEventHandler
import time
import requests
import math
import hashlib
import psutil
import os

from config import (
    DEVICE_NAME, SERVER_URL,
    THRESHOLD, TIME_WINDOW,
    RENAME_THRESHOLD, ENTROPY_THRESHOLD,
    VIRUSTOTAL_API_KEY
)

# -------------------------------
# 📊 Activity tracking
# -------------------------------
MODIFIED_FILES = []
RENAMED_FILES = []

LAST_API_CALL = 0  # ⏱️ rate limiting

SUSPICIOUS_EXTENSIONS = [".locked", ".enc", ".crypt", ".encrypted"]

SAFE_PROCESSES = ["bash", "systemd", "gnome-shell", "code", "python3"]


# -------------------------------
# 🔐 HASH
# -------------------------------
def get_file_hash(file_path):
    try:
        if not os.path.exists(file_path):
            return None

        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None


# -------------------------------
# 🌐 VIRUSTOTAL
# -------------------------------
def check_virustotal(file_path):
    global LAST_API_CALL

    # ⏱️ limit API calls (1 per 15 sec)
    if time.time() - LAST_API_CALL < 15:
        return

    file_hash = get_file_hash(file_path)
    if not file_hash:
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)

            print(f"🧪 VirusTotal: {malicious} engines flagged")

            if malicious > 0:
                print("🚨 MALICIOUS FILE DETECTED!")

                send_alert(file_path, "VirusTotal: Malware detected")

                for proc in get_suspicious_processes():
                    kill_process(proc)

        LAST_API_CALL = time.time()

    except Exception as e:
        print("API error:", e)


# -------------------------------
# 🔬 ENTROPY
# -------------------------------
def calculate_entropy(file_path):
    try:
        if not os.path.exists(file_path):
            return 0

        with open(file_path, "rb") as f:
            data = f.read(1024)

        if not data:
            return 0

        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        entropy = 0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        return entropy

    except:
        return 0


# -------------------------------
# 🔎 PROCESS TRACKING
# -------------------------------
def get_suspicious_processes():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
        try:
            io = proc.info['io_counters']
            if io and io.write_bytes > 5 * 1024 * 1024:
                suspicious.append(proc)
        except:
            continue

    return suspicious


# -------------------------------
# 🔪 AUTO KILL
# -------------------------------
def kill_process(proc):
    try:
        name = proc.name()

        if name in SAFE_PROCESSES:
            return

        print(f"🔥 Killing: {proc.pid} ({name})")
        proc.kill()

    except:
        pass


# -------------------------------
# 📡 ALERT
# -------------------------------
def send_alert(file_path, reason):
    data = {
        "device": DEVICE_NAME,
        "alerts": [{
            "time": time.strftime("%H:%M:%S"),
            "alert": reason,
            "file": file_path
        }]
    }

    try:
        requests.post(SERVER_URL, json=data)
        print("📡 Alert sent:", reason)
    except:
        print("⚠️ Server not reachable")


# -------------------------------
# 🧠 DETECTION
# -------------------------------
def check_extension(file_path):
    for ext in SUSPICIOUS_EXTENSIONS:
        if file_path.endswith(ext):
            send_alert(file_path, "Suspicious extension")


def check_ransomware(file_path):
    current_time = time.time()

    global MODIFIED_FILES, RENAMED_FILES

    MODIFIED_FILES = [t for t in MODIFIED_FILES if current_time - t < TIME_WINDOW]
    RENAMED_FILES = [t for t in RENAMED_FILES if current_time - t < TIME_WINDOW]

    if len(MODIFIED_FILES) > THRESHOLD and len(RENAMED_FILES) > RENAME_THRESHOLD:
        print("🚨 RANSOMWARE DETECTED!")
        send_alert(file_path, "Ransomware detected")
        time.sleep(0.3)
        for proc in get_suspicious_processes():
            kill_process(proc)


# -------------------------------
# 📂 HANDLER
# -------------------------------
class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, send_alert_func):
        self.send_alert = send_alert_func
        

    def on_modified(self, event):
        if not event.is_directory:
            MODIFIED_FILES.append(time.time())

            entropy = calculate_entropy(event.src_path)
            print(f"[MODIFIED] {event.src_path} | Entropy: {entropy:.2f}")

            # 🔥 Smart API call
            if entropy > 6:
                check_virustotal(event.src_path)

            if entropy > ENTROPY_THRESHOLD:
                send_alert(event.src_path, "High entropy")

            check_extension(event.src_path)
            check_ransomware(event.src_path)


    def on_moved(self, event):
        if not event.is_directory:
            RENAMED_FILES.append(time.time())

            print(f"[RENAMED] {event.dest_path}")

            check_extension(event.dest_path)
            check_virustotal(event.dest_path)
            check_ransomware(event.dest_path)