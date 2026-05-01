from flask import Flask, render_template
from flask_socketio import SocketIO
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret123"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)