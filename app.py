"""
app.py — Application entrypoint.
Run: python app.py
Then open http://localhost:3000
"""

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


@app.get("/api/health")
def health_check():
    return {"status": "ok"}
@app.errorhandler(404)
def not_found(e):
    return app.send_static_file("404.html"), 404

if __name__ == "__main__":
    print(f"\nRisk-Based 2FA prototype running at http://localhost:{config.PORT}")
    if config.ALLOW_DEBUG_IP:
        print("ALLOW_DEBUG_IP is on — use Simulate IP on the login page.\n")
    app.run(host="0.0.0.0", port=config.PORT, debug=True)