from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

devices = {}
alerts = []


@app.route("/")
def index():
    return render_template("index.html")

# Agent reporting
@app.route("/report", methods=["POST"])
def report():
    data = request.json
    device = data["device"]
    device_alerts = data["alerts"]

    devices[device] = {
        "status": "⚠️ ALERT" if device_alerts else "CLEAN",
        "status_class": "danger" if device_alerts else "clean",
        "ip": request.remote_addr
    }

    for a in device_alerts:
        alert = {
            "time": a.get("time"),
            "device": device,
            "alert": a.get("alert"),
            "file": a.get("file")
        }
        alerts.append(alert)

        # 🔥 REAL-TIME PUSH
        socketio.emit("new_alert", alert)
        print("🚨 Emitting alert:", alert)

    return {"status": "ok"}


@app.route("/status")
def status():
    return jsonify({
        "devices": devices,
        "alerts": alerts[-20:]
    })


@app.route("/clear_alerts", methods=["POST"])
def clear():
    alerts.clear()
    return {"status": "cleared"}


# 🔥 CONTROL: Kill process remotely
@app.route("/kill", methods=["POST"])
def kill():
    data = request.json
    socketio.emit("kill_process", data)
    return {"status": "sent"}


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)