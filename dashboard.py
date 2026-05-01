# dashboard.py
from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret123"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

@app.route("/")
def index():
    return render_template("index.html")

def emit_packet(features, is_anomaly, score, model_name):
    """Call this whenever a packet is processed."""
    socketio.emit("packet", {
        "src_ip":     features.get("src_ip", "?"),
        "dst_ip":     features.get("dst_ip", "?"),
        "protocol":   features.get("protocol", "?"),
        "src_port":   features.get("src_port", 0),
        "dst_port":   features.get("dst_port", 0),
        "pkt_size":   features.get("pkt_size", 0),
        "is_anomaly": is_anomaly,
        "score":      round(score, 4),
        "model":      model_name
    })

def emit_blocked(ip, reason):
    """Call this when an IP is blocked."""
    socketio.emit("blocked", {"ip": ip, "reason": reason})

def run_dashboard():
    """Run Flask in background thread."""
    socketio.run(app, host="0.0.0.0", port=5000, use_reloader=False)