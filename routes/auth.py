"""routes/auth.py — Registration, login, OTP verification, TOTP setup, logout."""

import json, uuid
import bcrypt
from flask import Blueprint, jsonify, request, session
from db import get_db
from services.geo_service import resolve_client_ip, lookup_geo
from services.device_service import compute_device_hash
from services.risk_engine import assess_risk, required_factors_for_tier
import services.otp_service as otp

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def require_auth(fn):
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error":"Not authenticated"}), 401
        return fn(*args, **kwargs)
    wrapped.__name__ = fn.__name__
    return wrapped


@auth_bp.post("/register")
def register():
    b = request.get_json(force=True, silent=True) or {}
    username, email, password, phone = b.get("username"), b.get("email"), b.get("password"), b.get("phone")
    if not username or not email or not password:
        return jsonify({"error":"username, email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error":"Password must be at least 8 characters"}), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE username=? OR email=?",(username,email)).fetchone():
        return jsonify({"error":"Username or email already registered"}), 409
    ph  = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    cur = db.execute("INSERT INTO users (username,email,phone,password_hash) VALUES (?,?,?,?)",(username,email,phone,ph))
    db.commit()
    session["user_id"] = cur.lastrowid
    return jsonify({"message":"Registered","userId":cur.lastrowid}), 201


@auth_bp.post("/totp/setup")
@require_auth
def totp_setup():
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    secret = otp.generate_totp_secret()
    db.execute("UPDATE users SET totp_secret=? WHERE id=?",(secret,user["id"]))
    db.commit()
    uri = otp.totp_provisioning_uri(secret, user["username"])
    return jsonify({"secretBase32":secret,"otpauthUrl":uri,"qrDataUrl":otp.totp_uri_to_qr_data_url(uri)})


@auth_bp.post("/totp/confirm")
@require_auth
def totp_confirm():
    b    = request.get_json(force=True, silent=True) or {}
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if not user["totp_secret"]:
        return jsonify({"error":"Run /totp/setup first"}), 400
    if not otp.verify_totp(user["totp_secret"], b.get("token")):
        return jsonify({"error":"Invalid code"}), 400
    db.execute("UPDATE users SET totp_enabled=1 WHERE id=?",(user["id"],))
    db.commit()
    return jsonify({"message":"TOTP enabled"})


@auth_bp.post("/login")
def login():
    b        = request.get_json(force=True, silent=True) or {}
    username = b.get("username")
    password = b.get("password")
    if not username or not password:
        return jsonify({"error":"username and password required"}), 400
    db    = get_db()
    user  = db.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
    ip    = resolve_client_ip()
    geo   = lookup_geo(ip)
    dhash = compute_device_hash()

    def log_fail(outcome, uid=None):
        _log(db,uid,username,ip,geo,dhash,outcome=outcome)

    if user is None:
        log_fail("failed_password")
        return jsonify({"error":"Invalid credentials"}), 401
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        log_fail("failed_password", user["id"])
        return jsonify({"error":"Invalid credentials"}), 401

    risk  = assess_risk(user["id"], dhash, geo)
    score, tier, reasons = risk["score"], risk["tier"], risk["reasons"]

    if tier == "CRITICAL":
        _log(db,user["id"],username,ip,geo,dhash,outcome="blocked",
             score=score,tier=tier,reasons=reasons,required_factors=["blocked"])
        return jsonify({"error":"Login blocked: critical risk detected.",
                        "riskScore":score,"riskTier":tier,"reasons":reasons}), 403

    if tier == "LOW":
        _complete_login(user,ip,geo,dhash,score,tier,reasons,["password"])
        return jsonify({"status":"authenticated","riskScore":score,"riskTier":tier,
                        "reasons":reasons,"location":_geo_label(geo)})

    return _start_challenge(db,user,ip,geo,dhash,score,tier,reasons)


def _start_challenge(db,user,ip,geo,dhash,score,tier,reasons):
    required  = [f for f in required_factors_for_tier(tier) if f != "password"]
    dev_hints = {}
    if "totp" in required and not user["totp_enabled"]:
        required = ["email_otp" if f == "totp" else f for f in required]
    email_hash=email_exp=sms_hash=sms_exp=None
    if "otp_any" in required or "email_otp" in required:
        code,email_hash,email_exp = otp.send_email_otp(user["email"])
        dev_hints["emailOtp"] = code
    if "sms_otp" in required:
        code,sms_hash,sms_exp = otp.send_sms_otp(user["phone"])
        dev_hints["smsOtp"] = code
    token = str(uuid.uuid4())
    db.execute("""INSERT INTO pending_challenges
        (token,user_id,required_factors,satisfied_factors,email_otp_hash,email_otp_expires,
         sms_otp_hash,sms_otp_expires,ip,country,region,city,lat,lon,isp,timezone,device_hash,
         risk_score,risk_tier,risk_reasons)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (token,user["id"],json.dumps(required),json.dumps([]),email_hash,email_exp,
         sms_hash,sms_exp,ip,geo["country"],geo["region"],geo["city"],
         geo["lat"],geo["lon"],geo.get("isp"),geo.get("timezone"),
         dhash,score,tier,json.dumps(reasons)))
    db.commit()
    return jsonify({"status":"challenge_required","pendingToken":token,
                    "riskScore":score,"riskTier":tier,"reasons":reasons,
                    "requiredFactors":required,"totpAvailable":bool(user["totp_enabled"]),
                    "location":_geo_label(geo),"devHints":dev_hints})


@auth_bp.post("/verify")
def verify():
    b      = request.get_json(force=True, silent=True) or {}
    token  = b.get("pendingToken")
    db     = get_db()
    pending = db.execute("SELECT * FROM pending_challenges WHERE token=?",(token,)).fetchone()
    if not pending:
        return jsonify({"error":"Invalid or expired challenge"}), 400
    user      = db.execute("SELECT * FROM users WHERE id=?",(pending["user_id"],)).fetchone()
    required  = json.loads(pending["required_factors"])
    satisfied = set(json.loads(pending["satisfied_factors"]))
    if b.get("totpCode") and user["totp_enabled"]:
        if otp.verify_totp(user["totp_secret"], b.get("totpCode")):
            satisfied.add("totp")
            if "otp_any" in required: satisfied.add("otp_any")
    if b.get("emailOtp") and pending["email_otp_hash"]:
        if otp.verify_hashed_otp(b.get("emailOtp"),pending["email_otp_hash"],pending["email_otp_expires"]):
            satisfied.add("email_otp")
            if "otp_any" in required: satisfied.add("otp_any")
    if b.get("smsOtp") and pending["sms_otp_hash"]:
        if otp.verify_hashed_otp(b.get("smsOtp"),pending["sms_otp_hash"],pending["sms_otp_expires"]):
            satisfied.add("sms_otp")
    db.execute("UPDATE pending_challenges SET satisfied_factors=? WHERE token=?",(json.dumps(list(satisfied)),token))
    db.commit()
    missing = [f for f in required if f not in satisfied]
    if missing:
        return jsonify({"error":"Invalid code","missing":missing}), 401
    geo = {k:pending[k] for k in ("country","region","city","lat","lon","isp","timezone")}
    _complete_login(user,pending["ip"],geo,pending["device_hash"],
                    pending["risk_score"],pending["risk_tier"],
                    json.loads(pending["risk_reasons"]),required)
    db.execute("DELETE FROM pending_challenges WHERE token=?",(token,))
    db.commit()
    return jsonify({"status":"authenticated"})


@auth_bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"message":"Logged out"})


@auth_bp.get("/me")
@require_auth
def me():
    db   = get_db()
    user = db.execute("SELECT id,username,email,phone,totp_enabled FROM users WHERE id=?",(session["user_id"],)).fetchone()
    last = db.execute("SELECT city,country,isp,timezone,ip,risk_tier,risk_score,timestamp FROM login_logs WHERE user_id=? AND outcome='success' ORDER BY timestamp DESC LIMIT 1",(session["user_id"],)).fetchone()
    return jsonify({"user":dict(user),"lastLogin":dict(last) if last else None})


def _geo_label(geo):
    parts = [p for p in [geo.get("city"),geo.get("country")] if p and p not in ("Local Network","Unknown")]
    return ", ".join(parts) if parts else "Unknown location"

def _log(db,user_id,username,ip,geo,dhash,outcome,score=None,tier=None,reasons=None,required_factors=None):
    db.execute("""INSERT INTO login_logs
        (user_id,username_attempted,ip,country,region,city,lat,lon,isp,timezone,
         device_hash,risk_score,risk_tier,risk_reasons,required_factors,outcome)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (user_id,username,ip,geo.get("country"),geo.get("region"),geo.get("city"),
         geo.get("lat"),geo.get("lon"),geo.get("isp"),geo.get("timezone"),
         dhash,score,tier,
         json.dumps(reasons) if reasons is not None else None,
         json.dumps(required_factors) if required_factors is not None else None,
         outcome))
    db.commit()

def _complete_login(user,ip,geo,dhash,score,tier,reasons,required_factors):
    db = get_db()
    session["user_id"] = user["id"]
    db.execute("INSERT OR IGNORE INTO known_devices (user_id,device_hash) VALUES (?,?)",(user["id"],dhash))
    db.execute("UPDATE known_devices SET last_seen=datetime('now') WHERE user_id=? AND device_hash=?",(user["id"],dhash))
    _log(db,user["id"],user["username"],ip,geo,dhash,outcome="success",
         score=score or 0,tier=tier or "LOW",reasons=reasons or [],required_factors=required_factors or ["password"])