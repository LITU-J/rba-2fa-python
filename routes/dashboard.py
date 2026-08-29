"""routes/dashboard.py — Login history and known devices."""
import json
from flask import Blueprint, jsonify, session
from db import get_db
from routes.auth import require_auth

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

@dashboard_bp.get("/history")
@require_auth
def history():
    db   = get_db()
    rows = db.execute("""SELECT timestamp,ip,country,region,city,isp,timezone,
        device_hash,risk_score,risk_tier,required_factors,outcome
        FROM login_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50""",
        (session["user_id"],)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["required_factors"] = json.loads(d["required_factors"]) if d["required_factors"] else []
        if d["device_hash"]: d["device_hash"] = d["device_hash"][:10] + "…"
        result.append(d)
    return jsonify({"history":result})

@dashboard_bp.get("/known-devices")
@require_auth
def known_devices():
    db   = get_db()
    rows = db.execute("SELECT device_hash,first_seen,last_seen FROM known_devices WHERE user_id=? ORDER BY last_seen DESC",(session["user_id"],)).fetchall()
    return jsonify({"devices":[{**dict(r),"device_hash":r["device_hash"][:10]+"…"} for r in rows]})