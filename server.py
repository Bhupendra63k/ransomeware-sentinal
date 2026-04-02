"""
RansomSentinel — Backend Server
app.py | Flask + SocketIO + MongoDB
"""

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import time

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
socketio = SocketIO(app, cors_allowed_origins="*")

# ─── MongoDB ───
client = MongoClient("mongodb://localhost:27017/")
db = client["ransomware_db"]
alerts_col = db["alerts"]
devices_col = db["devices"]

# ─── In-memory state (for fast reads) ───
devices = {}
alerts = []


# ══════════════════════════════════
# ROUTES — Frontend
# ══════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ══════════════════════════════════
# ROUTES — Agent API
# ══════════════════════════════════

@app.route("/report", methods=["POST"])
def report():
    """Receive alerts from the agent."""
    try:
        data = request.get_json(force=True)
        device = data.get("device", "unknown")
        ip = data.get("ip", request.remote_addr or "N/A")
        os_info = data.get("os", "Unknown")
        device_alerts = data.get("alerts", [])

        print(f"📩 REPORT from {device} ({ip}) | {len(device_alerts)} alert(s)")

        # Update / upsert device record
        devices_col.update_one(
            {"name": device},
            {"$set": {
                "name": device,
                "ip": ip,
                "os": os_info,
                "last_seen": datetime.now().strftime("%H:%M:%S"),
                "online": True,
                "status": "CLEAN",
                "status_class": "clean"
            }},
            upsert=True
        )

        for a in device_alerts:
            # Prevent duplicate active alerts for same file + alert type
            existing = alerts_col.find_one({
                "device": device,
                "file": a.get("file"),
                "alert": a.get("alert"),
                "status": "active"
            })
            if existing:
                print(f"  ⏩ Duplicate skipped: {a.get('alert')}")
                continue

            severity = a.get("severity") or infer_severity(a.get("alert", ""))

            alert_doc = {
                "device": device,
                "time": a.get("time", datetime.now().strftime("%H:%M:%S")),
                "alert": a.get("alert"),
                "file": a.get("file"),
                "severity": severity,
                "created_at": datetime.now().isoformat(),
                "status": "active"
            }
            result = alerts_col.insert_one(alert_doc)
            alert_doc["_id"] = str(result.inserted_id)

            # Mark device as under attack
            devices_col.update_one(
                {"name": device},
                {"$set": {"status": "UNDER ATTACK", "status_class": "danger"}}
            )

            print(f"  💾 Saved alert: {a.get('alert')} | severity={severity}")

            # Emit real-time event
            socketio.emit("new_alert", alert_doc)

        return jsonify({"status": "ok"})

    except Exception as e:
        print(f"❌ ERROR in /report: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    """Agent heartbeat — keeps device online status fresh."""
    try:
        data = request.get_json(force=True)
        device = data.get("device", "unknown")
        ip = data.get("ip", request.remote_addr or "N/A")

        devices_col.update_one(
            {"name": device},
            {"$set": {
                "ip": ip,
                "last_seen": datetime.now().strftime("%H:%M:%S"),
                "online": True
            }},
            upsert=True
        )
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════
# ROUTES — Dashboard API
# ══════════════════════════════════

@app.route("/status")
def status():
    try:
        # 🔥 Get devices from MongoDB
        devices = list(devices_col.find({}, {"_id": 0}))

        # 🔥 Get active alerts
        alerts = list(alerts_col.find(
            {"status": "active"},
            {"_id": 1, "device": 1, "alert": 1, "file": 1, "time": 1}
        ))

        # convert ObjectId → string
        for a in alerts:
            a["_id"] = str(a["_id"])

        return jsonify({
            "devices": devices,
            "alerts": alerts
        })

    except Exception as e:
        print("❌ ERROR in /status:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/get_alerts")
def get_alerts():
    """Return all active alerts."""
    data = list(alerts_col.find(
        {"status": "active"},
        {"_id": 1, "device": 1, "alert": 1, "file": 1,
         "time": 1, "severity": 1, "created_at": 1, "status": 1}
    ).sort("created_at", -1).limit(100))

    for d in data:
        d["_id"] = str(d["_id"])

    return jsonify(data)


@app.route("/get_resolved_alerts")
def get_resolved_alerts():
    """Return resolved alerts for history view."""
    data = list(alerts_col.find(
        {"status": "resolved"},
        {"_id": 1, "device": 1, "alert": 1, "file": 1,
         "time": 1, "severity": 1, "created_at": 1, "status": 1}
    ).sort("created_at", -1).limit(100))

    for d in data:
        d["_id"] = str(d["_id"])

    return jsonify(data)


@app.route("/resolve_alert", methods=["POST"])
def resolve_alert():
    try:
        data = request.get_json()
        alert_id = data.get("id")

        if not alert_id:
            print("❌ Invalid ID received")
            return jsonify({"error": "Invalid ID"}), 400

        try:
            obj_id = ObjectId(alert_id)
        except Exception:
            print("❌ Invalid ObjectId format:", alert_id)
            return jsonify({"error": "Invalid ObjectId"}), 400

        result = alerts_col.update_one(
            {"_id": obj_id},
            {"$set": {"status": "resolved", "resolved_at": datetime.now().isoformat()}}
        )

        print(f"✅ Resolved alert: {alert_id} | Modified: {result.modified_count}")

        return jsonify({"status": "resolved"})

    except Exception as e:
        print(f"❌ ERROR in /resolve_alert: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/clear_alerts", methods=["POST"])
def clear_alerts():
    """Clear all active alerts."""
    alerts_col.update_many({"status": "active"}, {"$set": {"status": "cleared"}})
    devices_col.update_many({}, {"$set": {"status": "CLEAN", "status_class": "clean"}})
    return jsonify({"status": "cleared"})


@app.route("/kill", methods=["POST"])
def kill_process():
    """Send kill command to agent via SocketIO."""
    data = request.get_json()
    socketio.emit("kill_process", data)
    return jsonify({"status": "kill_sent"})


# ══════════════════════════════════
# UTILITIES
# ══════════════════════════════════

def infer_severity(alert_text: str) -> str:
    """Infer severity level from alert text."""
    t = alert_text.lower()
    if any(k in t for k in ["ransomware", "malware", "critical", "virustotal"]):
        return "high"
    if any(k in t for k in ["entropy", "virus", "suspicious", "extension"]):
        return "medium"
    return "low"


def mark_offline_devices():
    """Mark devices as offline if not seen in 60 seconds."""
    threshold = datetime.now() - timedelta(seconds=60)
    # In a production system, use proper timestamps for this


# ══════════════════════════════════
# MAIN
# ══════════════════════════════════

if __name__ == "__main__":
    print("🚀 RansomSentinel Server starting on port 5000...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)