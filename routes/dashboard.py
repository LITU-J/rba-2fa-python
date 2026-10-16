"""routes/dashboard.py — Dashboard API"""
from flask import Blueprint, jsonify, session, request
from db import get_db
import math

dashboard_bp = Blueprint("dashboard_bp", __name__, url_prefix="/api/dashboard")


def _require_auth():
    uid = session.get("user_id")
    if not uid:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    db = get_db()
    sess_uuid = session.get("session_uuid", "")
    row = db.execute(
        "SELECT * FROM active_sessions WHERE user_id=? AND is_active=1 AND session_uuid=?",
        (uid, sess_uuid)
    ).fetchone()
    if not row:
        return None, (jsonify({"error": "Session expired"}), 401)
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return user, None


@dashboard_bp.route("/overview")
def overview():
    user, err = _require_auth()
    if err: return err
    db = get_db()
    device_count = db.execute(
        "SELECT COUNT(*) FROM known_devices WHERE user_id=?", (user["id"],)
    ).fetchone()[0]
    last_login = db.execute("""
        SELECT risk_score, risk_tier, city, country, isp, timestamp
        FROM login_logs WHERE user_id=? AND outcome='success'
        ORDER BY timestamp DESC LIMIT 1
    """, (user["id"],)).fetchone()
    return jsonify({
        "username": user["username"],
        "totp_enabled": bool(user["totp_enabled"]),
        "device_count": device_count,
        "last_login": dict(last_login) if last_login else {}
    })


@dashboard_bp.route("/recent-activity")
def recent_activity():
    user, err = _require_auth()
    if err: return err
    db = get_db()
    rows = db.execute("""
        SELECT timestamp, outcome, auth_method, city, country, risk_tier, risk_score
        FROM login_logs WHERE user_id=?
        ORDER BY timestamp DESC LIMIT 5
    """, (user["id"],)).fetchall()
    return jsonify({"events": [dict(r) for r in rows]})


@dashboard_bp.route("/login-history")
def login_history():
    user, err = _require_auth()
    if err: return err
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(1, int(request.args.get("per_page", 20)))
    offset = (page - 1) * per_page
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM login_logs WHERE user_id=?", (user["id"],)).fetchone()[0]
    rows = db.execute("""
        SELECT timestamp, outcome, auth_method, ip, city, country, isp, risk_tier, risk_score
        FROM login_logs WHERE user_id=?
        ORDER BY timestamp DESC LIMIT ? OFFSET ?
    """, (user["id"], per_page, offset)).fetchall()
    pages = math.ceil(total / per_page) if total > 0 else 1
    return jsonify({"history": [dict(r) for r in rows], "total": total, "pages": pages, "current_page": page})


@dashboard_bp.route("/known-devices")
def known_devices():
    user, err = _require_auth()
    if err: return err
    db = get_db()
    rows = db.execute("""
        SELECT substr(device_hash, 1, 8) AS device_hash_prefix, device_hash,
               last_seen, COALESCE(login_count, 1) AS login_count
        FROM known_devices WHERE user_id=?
        ORDER BY last_seen DESC
    """, (user["id"],)).fetchall()
    devices = []
    for r in rows:
        d = dict(r)
        d["device_label"] = "Unknown Device"
        d["first_seen"] = d.get("last_seen")
        devices.append(d)
    return jsonify({"devices": devices})


@dashboard_bp.route("/devices/revoke", methods=["POST"])
def revoke_device():
    user, err = _require_auth()
    if err: return err
    data = request.get_json() or {}
    prefix = data.get("device_hash_prefix", "")
    if not prefix: return jsonify({"error": "Missing device_hash_prefix"}), 400
    db = get_db()
    db.execute("DELETE FROM known_devices WHERE user_id=? AND device_hash LIKE ?", (user["id"], prefix + "%"))
    db.commit()
    return jsonify({"ok": True})


@dashboard_bp.route("/sessions")
def sessions():
    user, err = _require_auth()
    if err: return err
    db = get_db()
    current_uuid = session.get("session_uuid", "")
    rows = db.execute("""
        SELECT session_uuid, ip, country, city, isp, user_agent,
               last_active, is_active,
               CASE WHEN session_uuid=? THEN 1 ELSE 0 END AS is_current
        FROM active_sessions
        WHERE user_id=? AND is_active=1
        ORDER BY last_active DESC
    """, (current_uuid, user["id"])).fetchall()
    return jsonify({"sessions": [dict(r) for r in rows], "current_session_uuid": current_uuid})


@dashboard_bp.route("/sessions/revoke", methods=["POST"])
def revoke_session():
    user, err = _require_auth()
    if err: return err
    data = request.get_json() or {}
    uuid = data.get("session_uuid", "")
    if not uuid: return jsonify({"error": "Missing session_uuid"}), 400
    current_uuid = session.get("session_uuid", "")
    if uuid == current_uuid: return jsonify({"error": "Cannot revoke your current session"}), 400
    db = get_db()
    db.execute("UPDATE active_sessions SET is_active=0 WHERE session_uuid=? AND user_id=?", (uuid, user["id"]))
    db.commit()
    return jsonify({"ok": True})


@dashboard_bp.route("/risk-trend")
def risk_trend():
    user, err = _require_auth()
    if err: return err
    db = get_db()
    rows = db.execute("""
        SELECT timestamp, risk_score, risk_tier FROM login_logs
        WHERE user_id=? AND outcome='success'
        ORDER BY timestamp DESC LIMIT 30
    """, (user["id"],)).fetchall()
    return jsonify({"trend": list(reversed([dict(r) for r in rows]))})


@dashboard_bp.route("/admin/stats")
def admin_stats():
    user, err = _require_auth()
    if err: return err
    if not user["is_admin"]:
        return jsonify({"error": "Access denied — admin only."}), 403
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_logins = db.execute("SELECT COUNT(*) FROM login_logs WHERE outcome='success'").fetchone()[0]
    totp_users = db.execute("SELECT COUNT(*) FROM users WHERE totp_enabled=1").fetchone()[0]
    locked_users = db.execute("SELECT COUNT(DISTINCT user_id) FROM login_logs WHERE outcome='blocked'").fetchone()[0]
    tier_rows = db.execute("SELECT risk_tier, COUNT(*) AS cnt FROM login_logs WHERE outcome='success' GROUP BY risk_tier").fetchall()
    tier_breakdown = {r["risk_tier"]: r["cnt"] for r in tier_rows if r["risk_tier"]}
    for t in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        tier_breakdown.setdefault(t, 0)
    return jsonify({
        "total_users": total_users, "total_logins": total_logins,
        "totp_users": totp_users, "locked_users": locked_users,
        "tier_breakdown": tier_breakdown
    })


@dashboard_bp.route("/admin/users")
def admin_users():
    user, err = _require_auth()
    if err: return err
    if not user["is_admin"]:
        return jsonify({"error": "Access denied — admin only."}), 403
    db = get_db()
    rows = db.execute("""
        SELECT id, username, email, COALESCE(totp_enabled, 0) AS totp_enabled,
               (SELECT COUNT(*) FROM login_logs WHERE user_id=users.id AND outcome='success') AS login_count,
               (SELECT MAX(timestamp) FROM login_logs WHERE user_id=users.id AND outcome='success') AS last_login
        FROM users ORDER BY id
    """).fetchall()
    return jsonify({"users": [dict(r) for r in rows]})