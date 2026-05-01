import os
from flask import Flask, render_template

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret123"

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
