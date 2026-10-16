"""
app.py — Application entrypoint.
Run: python app.py
Then open http://localhost:3000
"""

import os
from flask import Flask
import config
from db import init_db
from routes.auth       import auth_bp
from routes.dashboard  import dashboard_bp
from routes.evaluation import evaluation_bp
from routes.sus        import sus_bp

app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = config.SECRET_KEY

init_db(app)

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(evaluation_bp)
app.register_blueprint(sus_bp)


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.errorhandler(404)
def not_found(e):
    return app.send_static_file("404.html"), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    print(f"\n  Risk-Based 2FA running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)