from watchdog.observers import Observer
from monitor import RansomwareHandler
import time
import os
import requests

from config import SERVER_URL, DEVICE_NAME

# 📂 Folder to monitor
PATH_TO_MONITOR = os.path.expanduser("~/test_folder")


# -------------------------------
# 🌐 SERVER CHECK
# -------------------------------
def check_server():
    try:
        res = requests.get(SERVER_URL.replace("/alert", "/status"), timeout=3)
        print("🌐 Server connected")
        return True
    except:
        print("⚠️ Server not reachable")
        return False


# -------------------------------
# 🚀 MAIN AGENT
# -------------------------------
def main():
    print("🛡️ Ransomware Agent Starting...")
    print(f"💻 Device: {DEVICE_NAME}")
    print(f"📂 Monitoring: {PATH_TO_MONITOR}")

    # Ensure folder exists
    if not os.path.exists(PATH_TO_MONITOR):
        print("📁 Creating monitoring folder...")
        os.makedirs(PATH_TO_MONITOR)

    # Check server
    check_server()

    # Setup observer
    event_handler = RansomwareHandler()
    observer = Observer()

    observer.schedule(event_handler, PATH_TO_MONITOR, recursive=True)

    try:
        observer.start()
        print("🟢 Agent running... Press CTRL+C to stop")

        while True:
            time.sleep(1)

    except Exception as e:
        print(f"❌ Error: {e}")

    except KeyboardInterrupt:
        print("\n🛑 Stopping agent...")

    finally:
        observer.stop()
        observer.join()
        print("🔴 Agent stopped cleanly")


# -------------------------------
# ▶️ RUN
# -------------------------------
if __name__ == "__main__":
    main()