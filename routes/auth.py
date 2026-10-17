"""
routes/auth.py
===============
Registration, login, OTP verification, TOTP setup, logout.
Password reset with email verification.
Time-based account lockout — 15 minutes after 5 failures.
Velocity check, geofencing, IP reputation, login alerts.
"""

import json
import uuid
import bcrypt
import smtplib
import secrets as _secrets_module
import threading
import ipaddress
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Blueprint, jsonify, request, session
from db import get_db
from services.geo_service import resolve_client_ip, lookup_geo
from services.device_service import compute_device_hash
from services.risk_engine import assess_risk, required_factors_for_tier
import services.otp_service as otp
import config

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

LOCKOUT_MINUTES  = 15
LOCKOUT_ATTEMPTS = 5
SPECIAL_CHARS    = "!@#$%^&*()_+-=[]{}|;':\",./<>?"


def require_auth(fn):
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Not authenticated"}), 401
        sess_uuid = session.get("session_uuid")
        if sess_uuid:
            db = get_db()
            row = db.execute(
                "SELECT is_active FROM active_sessions WHERE session_uuid=?",
                (sess_uuid,)
            ).fetchone()
            if row and not row["is_active"]:
                session.clear()
                return jsonify({"error": "Session revoked", "revoked": True}), 401
        return fn(*args, **kwargs)
    wrapped.__name__ = fn.__name__
    return wrapped


# ------------------------------------------------------------------
# Password validator
# ------------------------------------------------------------------

def _validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in SPECIAL_CHARS for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*)"
    return True, None


# ------------------------------------------------------------------
# Lockout helper
# ------------------------------------------------------------------

def _check_lockout(db, user_id):
    recent = db.execute(
        "SELECT outcome, timestamp FROM login_logs "
        "WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
        (user_id, LOCKOUT_ATTEMPTS)
    ).fetchall()

    if len(recent) < LOCKOUT_ATTEMPTS:
        return {"locked": False}

    all_failed = all(
        r["outcome"] and r["outcome"].startswith("failed")
        for r in recent
    )

    if not all_failed:
        return {"locked": False}

    latest_str  = recent[0]["timestamp"]
    latest_fail = datetime.strptime(
        latest_str, "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    unlock_time = latest_fail + timedelta(minutes=LOCKOUT_MINUTES)
    now         = datetime.now(timezone.utc)

    if now >= unlock_time:
        return {"locked": False}

    remaining_secs    = int((unlock_time - now).total_seconds())
    minutes_remaining = remaining_secs // 60
    seconds_remaining = remaining_secs % 60

    return {
        "locked":            True,
        "minutes_remaining": minutes_remaining,
        "seconds_remaining": seconds_remaining,
    }


# ------------------------------------------------------------------
# Tier escalation helper
# ------------------------------------------------------------------

def _escalate_tier(tier):
    tiers = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx   = tiers.index(tier) if tier in tiers else 0
    return tiers[min(idx + 1, 3)]


# ------------------------------------------------------------------
# Velocity check — impossible travel detection
# ------------------------------------------------------------------

def _check_velocity(db, user_id, current_country):
    if not current_country or current_country in ("Unknown", "Local Network"):
        return False
    recent = db.execute(
        "SELECT country, timestamp FROM login_logs "
        "WHERE user_id=? AND outcome='success' AND country IS NOT NULL "
        "AND country NOT IN ('Unknown', 'Local Network') "
        "ORDER BY timestamp DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    if not recent or recent["country"] == current_country:
        return False
    try:
        last_time = datetime.strptime(
            recent["timestamp"], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - last_time).total_seconds() < 7200:
            return True
    except Exception:
        pass
    return False


# ------------------------------------------------------------------
# Geofencing — new country never seen before (with continent detection)
# ------------------------------------------------------------------

def _get_continent(timezone_str):
    """Extract continent prefix from IANA timezone string."""
    if not timezone_str or "/" not in timezone_str:
        return None
    prefix = timezone_str.split("/")[0]
    continent_map = {
        "Africa": "Africa", "America": "Americas", "Antarctica": "Antarctica",
        "Arctic": "Arctic", "Asia": "Asia", "Atlantic": "Atlantic",
        "Australia": "Oceania", "Europe": "Europe", "Indian": "Indian",
        "Pacific": "Pacific", "US": "Americas", "Canada": "Americas",
    }
    return continent_map.get(prefix, prefix)


def _check_geofencing(db, user_id, current_country, current_timezone=None):
    if not current_country or current_country in ("Unknown", "Local Network"):
        return False, None
    total = db.execute(
        "SELECT COUNT(*) as cnt FROM login_logs WHERE user_id=? AND outcome='success'",
        (user_id,)
    ).fetchone()["cnt"]
    if total < 3:
        return False, None
    seen = db.execute(
        "SELECT DISTINCT country FROM login_logs WHERE user_id=? AND outcome='success'",
        (user_id,)
    ).fetchall()
    known_countries = {r["country"] for r in seen}
    if current_country not in known_countries:
        current_continent = _get_continent(current_timezone)
        if current_continent:
            seen_tzs = db.execute(
                "SELECT DISTINCT timezone FROM login_logs "
                "WHERE user_id=? AND outcome='success' AND timezone IS NOT NULL",
                (user_id,)
            ).fetchall()
            known_continents = {_get_continent(r["timezone"]) for r in seen_tzs if r["timezone"]}
            known_continents.discard(None)
            if known_continents and current_continent not in known_continents:
                return True, "different_continent"
        return True, "same_region"
    return False, None

# ------------------------------------------------------------------
# IP Reputation — proxy/VPN/hosting detection (ip-api.com, free)
# ------------------------------------------------------------------

def _check_ip_reputation(ip):
    result = {"proxy": False, "hosting": False, "mobile": False}
    if not ip or ip.startswith(("10.", "192.168.", "127.", "172.")):
        return result
    try:
        url = f"http://ip-api.com/json/{ip}?fields=proxy,hosting,mobile"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read())
            result["proxy"]   = bool(data.get("proxy"))
            result["hosting"] = bool(data.get("hosting"))
            result["mobile"]  = bool(data.get("mobile"))
    except Exception:
        pass
    return result


# ------------------------------------------------------------------
# Email helpers
# ------------------------------------------------------------------

def _smtp_send(to, msg):
    try:
        with smtplib.SMTP(config.SMTP_HOST, int(config.SMTP_PORT)) as s:
            s.ehlo(); s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.sendmail(config.SMTP_FROM, to, msg.as_string())
            return
    except Exception as e:
        print(f"[SMTP 587 failed] {e}")
    try:
        with smtplib.SMTP_SSL(config.SMTP_HOST, 465) as s:
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.sendmail(config.SMTP_FROM, to, msg.as_string())
    except Exception as e:
        print(f"[SMTP 465 failed] {e}")


def _send_reset_email(to, code):
    html = f"""
    <html><body style="font-family:Arial,sans-serif;padding:0;margin:0;background:#f4f6fb;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 0;">
    <table width="520" style="background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
      <tr><td style="background:linear-gradient(135deg,#1a3c8f,#2f5df0);padding:32px 40px;border-radius:16px 16px 0 0;text-align:center;">
        <h1 style="margin:0;color:#fff;font-size:22px;">RBA-2FA System</h1>
        <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">Password Reset Request</p>
      </td></tr>
      <tr><td style="padding:40px;">
        <p style="color:#374151;font-size:15px;">Hello,</p>
        <p style="color:#6b7386;font-size:14px;line-height:1.6;">You requested a password reset for your RBA-2FA account.</p>
        <div style="text-align:center;margin:28px 0;">
          <span style="display:inline-block;background:#f0f4ff;border:2px solid #2f5df0;border-radius:12px;padding:18px 40px;font-size:38px;font-weight:800;letter-spacing:10px;color:#1a3c8f;">{code}</span>
        </div>
        <p style="color:#6b7386;font-size:13px;text-align:center;">Expires in <strong>15 minutes</strong></p>
        <div style="background:#fff8e1;border:1px solid #ffd54f;border-radius:10px;padding:14px 18px;margin-top:20px;">
          <p style="margin:0;color:#856404;font-size:13px;">Never share this code with anyone.</p>
        </div>
        <hr style="border:none;border-top:1px solid #eef0f5;margin:28px 0;">
        <p style="color:#9aa3b5;font-size:12px;text-align:center;">If you did not request this — ignore this email.</p>
      </td></tr>
      <tr><td style="background:#f8f9fc;padding:20px;border-radius:0 0 16px 16px;text-align:center;">
        <p style="margin:0;color:#c0c5d0;font-size:11px;">RBA-2FA System — UNAM Research Prototype 2026</p>
      </td></tr>
    </table></td></tr></table>
    </body></html>"""

    plain = f"Your RBA-2FA password reset code is: {code}\nExpires in 15 minutes."
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "RBA-2FA Password Reset Code"
    msg["From"]    = config.SMTP_FROM
    msg["To"]      = to
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(to, msg)


def _send_login_alert_email(to, username, ip, city, country, device_is_new, alert_token):
    location   = f"{city}, {country}" if city and country else (country or ip or "Unknown")
    new_device = "<p style='color:#b45309;font-weight:700;'>⚠️ New device detected on your account.</p>" if device_is_new else ""
    app_url    = getattr(config, "APP_URL", "https://mjoseph.pythonanywhere.com")
    revoke_url = f"{app_url}/api/auth/revoke-alert?token={alert_token}"
    time_str   = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f6fb;padding:0;margin:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 0;">
    <table width="520" style="background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
      <tr><td style="background:linear-gradient(135deg,#7c3aed,#4f46e5);padding:32px 40px;border-radius:16px 16px 0 0;text-align:center;">
        <h1 style="margin:0;color:#fff;font-size:22px;">🔐 New Login Detected</h1>
        <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">RBA-2FA Security Alert</p>
      </td></tr>
      <tr><td style="padding:40px;">
        <p style="color:#374151;font-size:15px;">Hi <strong>{username}</strong>,</p>
        <p style="color:#6b7386;font-size:14px;line-height:1.6;">A successful login was just detected on your account.</p>
        {new_device}
        <div style="background:#f0f4ff;border:1px solid #c7d2fe;border-radius:12px;padding:20px;margin:20px 0;">
          <table width="100%" cellpadding="4" cellspacing="0">
            <tr><td style="color:#374151;font-size:13px;width:110px;"><strong>📍 Location</strong></td><td style="color:#4f46e5;font-size:13px;">{location}</td></tr>
            <tr><td style="color:#374151;font-size:13px;"><strong>🌐 IP Address</strong></td><td style="color:#4f46e5;font-size:13px;">{ip}</td></tr>
            <tr><td style="color:#374151;font-size:13px;"><strong>🕐 Time</strong></td><td style="color:#4f46e5;font-size:13px;">{time_str}</td></tr>
          </table>
        </div>
        <p style="color:#6b7386;font-size:14px;">If this was you, no action is needed.</p>
        <div style="text-align:center;margin:28px 0;">
          <a href="{revoke_url}" style="display:inline-block;background:linear-gradient(135deg,#dc2626,#b91c1c);color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:700;font-size:14px;">🚫 This wasn't me — Revoke Session</a>
        </div>
        <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:10px;padding:14px 18px;">
          <p style="margin:0;color:#991b1b;font-size:13px;">⚠️ If you did not log in, click the button above immediately to revoke all sessions and secure your account.</p>
        </div>
      </td></tr>
      <tr><td style="background:#f8f9fc;padding:20px;border-radius:0 0 16px 16px;text-align:center;">
        <p style="margin:0;color:#c0c5d0;font-size:11px;">RBA-2FA System — UNAM Research Prototype 2026</p>
      </td></tr>
    </table></td></tr></table>
    </body></html>"""

    plain = f"New login to your RBA-2FA account from {location} (IP: {ip}) at {time_str}. If this wasn't you: {revoke_url}"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔐 New Login Detected — RBA-2FA Security Alert"
    msg["From"]    = config.SMTP_FROM
    msg["To"]      = to
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(to, msg)
    print(f"[LOGIN ALERT] Sent to {to}")


# ------------------------------------------------------------------
# Register
# ------------------------------------------------------------------

@auth_bp.post("/register")
def register():
    b        = request.get_json(force=True, silent=True) or {}
    username = b.get("username")
    email    = b.get("email")
    password = b.get("password")
    phone    = b.get("phone")

    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400

    valid, err = _validate_password(password)
    if not valid:
        return jsonify({"error": err}), 400

    db = get_db()
    if db.execute(
        "SELECT id FROM users WHERE username=? OR email=?", (username, email)
    ).fetchone():
        return jsonify({"error": "Username or email already registered"}), 409

    ph  = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    cur = db.execute(
        "INSERT INTO users (username, email, phone, password_hash) VALUES (?,?,?,?)",
        (username, email, phone, ph)
    )
    db.commit()
    session["user_id"] = cur.lastrowid
    return jsonify({"message": "Registered", "userId": cur.lastrowid}), 201


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------

@auth_bp.post("/login")
def login():
    b        = request.get_json(force=True, silent=True) or {}
    username = b.get("username")
    password = b.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    db    = get_db()
    user  = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ip    = resolve_client_ip()
    geo   = lookup_geo(ip)

    # ── debug_location override (simulation only) ─────────────────────
    _DEMO_LOCATIONS = {
        "windhoek":   {"country": "Namibia",      "city": "Windhoek",
                       "timezone": "Africa/Windhoek",     "lat": -22.5597, "lon": 17.0832},
        "swakopmund": {"country": "Namibia",      "city": "Swakopmund",
                       "timezone": "Africa/Windhoek",     "lat": -22.6784, "lon": 14.5271},
        "sa":         {"country": "South Africa", "city": "Johannesburg",
                       "timezone": "Africa/Johannesburg",  "lat": -26.2041, "lon": 28.0473},
        "japan":      {"country": "Japan",        "city": "Tokyo",
                       "timezone": "Asia/Tokyo",           "lat":  35.6762, "lon": 139.6503},
    }
    debug_loc = request.args.get("debug_location", "").lower()
    if debug_loc in _DEMO_LOCATIONS:
        geo = {**geo, **_DEMO_LOCATIONS[debug_loc]}
    # ──────────────────────────────────────────────────────────────────

    dhash = compute_device_hash()
    if user:
        lockout = _check_lockout(db, user["id"])
        if lockout["locked"]:
            mins = lockout["minutes_remaining"]
            secs = lockout["seconds_remaining"]
            _log(db, user["id"], username, ip, geo, dhash,
                 outcome="blocked", score=100, tier="CRITICAL",
                 reasons=[f"Account locked — {mins}m {secs}s remaining"],
                 required_factors=["blocked"], auth_method=None)
            return jsonify({
                "error": f"Account temporarily locked. Try again in {mins}m {secs}s.",
                "locked": True,
                "minutes_remaining": mins,
                "seconds_remaining": secs,
                "riskScore": 100, "riskTier": "CRITICAL",
            }), 403
    if user is None:
        _log(db, None, username, ip, geo, dhash,
             outcome="failed_password", auth_method=None)
        return jsonify({"error": "Invalid credentials"}), 401
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        _log(db, user["id"], username, ip, geo, dhash,
             outcome="failed_password", score=0, tier="LOW",
             reasons=[], required_factors=[], auth_method="password")
        recent = db.execute(
            "SELECT outcome FROM login_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
            (user["id"], LOCKOUT_ATTEMPTS)
        ).fetchall()
        consecutive = sum(1 for r in recent if r["outcome"] and r["outcome"].startswith("failed"))
        remaining   = max(0, LOCKOUT_ATTEMPTS - consecutive)
        if consecutive >= LOCKOUT_ATTEMPTS:
            return jsonify({
                "error": f"Account temporarily locked for {LOCKOUT_MINUTES} minutes due to too many failed attempts.",
                "locked": True, "riskScore": 100, "riskTier": "CRITICAL",
                "attemptsRemaining": 0,
            }), 403
        warning = None
        if remaining <= 2:
            warning = f"⚠️ Warning: Only {remaining} attempt{'s' if remaining != 1 else ''} left before your account is locked for {LOCKOUT_MINUTES} minutes!"
        return jsonify({
            "error": "Invalid username or password.",
            "attemptsRemaining": remaining,
            "maxAttempts": LOCKOUT_ATTEMPTS,
            "lockoutMinutes": LOCKOUT_MINUTES,
            "warning": warning,
        }), 401

    # ── Risk assessment (7 indicators via risk_engine) ───────────────
    risk    = assess_risk(user["id"], dhash, geo)
    score   = risk["score"]
    tier    = risk["tier"]
    reasons = list(risk["reasons"])

    # ── IP Reputation (extra signal not in risk_engine) ──────────────
    ip_rep = _check_ip_reputation(ip)
    if ip_rep.get("proxy"):
        score   = min(score + 30, 100)
        reasons.append("🕵️ VPN/proxy/anonymizer detected")
        if tier in ("LOW", "MEDIUM"):
            tier = "HIGH"
    if ip_rep.get("hosting"):
        score   = min(score + 20, 100)
        reasons.append("🖥️ Hosting/datacenter IP detected")
        if tier == "LOW":
            tier = "MEDIUM"

    # ── Normalize tier to match final score ──────────────────────────
    _TIER_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    _score_tier = ("CRITICAL" if score >= 85 else
                   "HIGH"     if score >= 60 else
                   "MEDIUM"   if score >= 30 else "LOW")
    tier = _TIER_ORDER[max(_TIER_ORDER.index(tier), _TIER_ORDER.index(_score_tier))]

    if tier == "CRITICAL":
        _log(db, user["id"], username, ip, geo, dhash,
             outcome="blocked", score=score, tier=tier,
             reasons=reasons, required_factors=["blocked"], auth_method=None)
        return jsonify({
            "error": "Login blocked: critical risk detected.",
            "riskScore": score, "riskTier": tier, "reasons": reasons,
        }), 403

    if tier == "LOW":
        _complete_login(user, ip, geo, dhash, score, tier, reasons, ["password"])
        return jsonify({
            "status": "authenticated", "riskScore": score,
            "riskTier": tier, "reasons": reasons,
            "location": _geo_label(geo),
        })

    return _start_challenge(db, user, ip, geo, dhash, score, tier, reasons)


# ------------------------------------------------------------------
# OTP Challenge
# ------------------------------------------------------------------

def _start_challenge(db, user, ip, geo, dhash, score, tier, reasons):
    required = [f for f in required_factors_for_tier(tier) if f != "password"]

    if tier == "HIGH":
        if user["totp_enabled"]:
            required = ["totp", "email_otp"]
        elif user["phone"]:
            required = ["sms_otp", "email_otp"]
        else:
            required = ["email_otp"]
    elif tier == "MEDIUM":
        required = ["totp"] if user["totp_enabled"] else ["email_otp"]

    email_hash = email_exp = sms_hash = sms_exp = None
    if "email_otp" in required:
        _, email_hash, email_exp = otp.send_email_otp(user["email"])
    if "sms_otp" in required:
        _, sms_hash, sms_exp = otp.send_sms_otp(user["phone"])

    token = str(uuid.uuid4())
    db.execute("""
        INSERT INTO pending_challenges
            (token, user_id, required_factors, satisfied_factors,
             email_otp_hash, email_otp_expires,
             sms_otp_hash, sms_otp_expires,
             ip, country, region, city, lat, lon, isp, timezone,
             device_hash, risk_score, risk_tier, risk_reasons)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        token, user["id"],
        json.dumps(required), json.dumps([]),
        email_hash, email_exp, sms_hash, sms_exp,
        ip, geo["country"], geo["region"], geo["city"],
        geo["lat"], geo["lon"], geo.get("isp"), geo.get("timezone"),
        dhash, score, tier, json.dumps(reasons)
    ))
    db.commit()

    return jsonify({
        "status": "challenge_required",
        "pendingToken": token,
        "riskScore": score, "riskTier": tier,
        "reasons": reasons, "requiredFactors": required,
        "totpAvailable": bool(user["totp_enabled"]),
        "location": _geo_label(geo),
    })


# ------------------------------------------------------------------
# Verify OTP
# ------------------------------------------------------------------

@auth_bp.post("/verify")
def verify():
    b       = request.get_json(force=True, silent=True) or {}
    token   = b.get("pendingToken")
    db      = get_db()
    pending = db.execute(
        "SELECT * FROM pending_challenges WHERE token=?", (token,)
    ).fetchone()

    if not pending:
        return jsonify({"error": "Invalid or expired challenge"}), 400

    user      = db.execute("SELECT * FROM users WHERE id=?", (pending["user_id"],)).fetchone()
    required  = json.loads(pending["required_factors"])
    satisfied = set(json.loads(pending["satisfied_factors"]))

    if b.get("totpCode") and user["totp_enabled"]:
        if otp.verify_totp(user["totp_secret"], b.get("totpCode")):
            satisfied.add("totp")
            if "otp_any" in required:
                satisfied.add("otp_any")

    if b.get("emailOtp") and pending["email_otp_hash"]:
        if otp.verify_hashed_otp(b.get("emailOtp"), pending["email_otp_hash"], pending["email_otp_expires"]):
            satisfied.add("email_otp")
            if "otp_any" in required:
                satisfied.add("otp_any")

    if b.get("smsOtp") and pending["sms_otp_hash"]:
        if otp.verify_hashed_otp(b.get("smsOtp"), pending["sms_otp_hash"], pending["sms_otp_expires"]):
            satisfied.add("sms_otp")

    db.execute(
        "UPDATE pending_challenges SET satisfied_factors=? WHERE token=?",
        (json.dumps(list(satisfied)), token)
    )
    db.commit()

    missing = [f for f in required if f not in satisfied]
    if missing:
        return jsonify({"error": "Invalid code", "missing": missing}), 401

    geo = {k: pending[k] for k in ("country", "region", "city", "lat", "lon", "isp", "timezone")}
    _complete_login(
        user, pending["ip"], geo, pending["device_hash"],
        pending["risk_score"], pending["risk_tier"],
        json.loads(pending["risk_reasons"]), required
    )
    db.execute("DELETE FROM pending_challenges WHERE token=?", (token,))
    db.commit()
    return jsonify({"status": "authenticated"})


# ------------------------------------------------------------------
# Logout
# ------------------------------------------------------------------

@auth_bp.post("/logout")
def logout():
    sess_uuid = session.get("session_uuid")
    if sess_uuid:
        db = get_db()
        db.execute(
            "UPDATE active_sessions SET is_active=0 WHERE session_uuid=?",
            (sess_uuid,)
        )
        db.commit()
    session.clear()
    return jsonify({"message": "Logged out"})


# ------------------------------------------------------------------
# Me
# ------------------------------------------------------------------

@auth_bp.get("/me")
@require_auth
def me():
    db = get_db()
    sess_uuid = session.get("session_uuid")
    if sess_uuid:
        db.execute(
            "UPDATE active_sessions SET last_active=datetime('now') WHERE session_uuid=?",
            (sess_uuid,)
        )
        db.commit()

    user = db.execute(
        "SELECT id, username, email, phone, totp_enabled FROM users WHERE id=?",
        (session["user_id"],)
    ).fetchone()
    last = db.execute(
        "SELECT city, country, isp, timezone, ip, risk_tier, risk_score, timestamp "
        "FROM login_logs WHERE user_id=? AND outcome='success' "
        "ORDER BY timestamp DESC LIMIT 1",
        (session["user_id"],)
    ).fetchone()
    return jsonify({
        "user":      dict(user),
        "lastLogin": dict(last) if last else None,
    })


# ------------------------------------------------------------------
# Change password
# ------------------------------------------------------------------

@auth_bp.post("/change-password")
@require_auth
def change_password():
    b           = request.get_json(force=True, silent=True) or {}
    current_pwd = b.get("current_password", "")
    new_pwd     = b.get("new_password", "")

    if not current_pwd or not new_pwd:
        return jsonify({"error": "Both fields are required"}), 400

    valid, err = _validate_password(new_pwd)
    if not valid:
        return jsonify({"error": err}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if not bcrypt.checkpw(current_pwd.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt(rounds=12)).decode()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user["id"]))
    db.commit()
    return jsonify({"message": "Password updated successfully"})


# ------------------------------------------------------------------
# TOTP Setup
# ------------------------------------------------------------------

@auth_bp.post("/totp/setup")
@require_auth
def totp_setup():
    db     = get_db()
    user   = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    secret = otp.generate_totp_secret()
    db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user["id"]))
    db.commit()
    uri = otp.totp_provisioning_uri(secret, user["username"])
    return jsonify({
        "secretBase32": secret,
        "otpauthUrl":   uri,
        "qrDataUrl":    otp.totp_uri_to_qr_data_url(uri),
    })


@auth_bp.post("/totp/confirm")
@require_auth
def totp_confirm():
    b    = request.get_json(force=True, silent=True) or {}
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if not user["totp_secret"]:
        return jsonify({"error": "Run /totp/setup first"}), 400
    if not otp.verify_totp(user["totp_secret"], b.get("token")):
        return jsonify({"error": "Invalid code"}), 400

    db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["id"],))
    db.commit()

    codes = _generate_backup_codes_for(db, user["id"])
    return jsonify({"message": "TOTP enabled", "backupCodes": codes})


# ------------------------------------------------------------------
# TOTP Backup Codes
# ------------------------------------------------------------------

def _generate_backup_codes_for(db, user_id):
    db.execute("DELETE FROM totp_backup_codes WHERE user_id=?", (user_id,))
    codes = []
    for _ in range(8):
        raw  = _secrets_module.token_hex(4).upper()
        code = f"{raw[:4]}-{raw[4:]}"
        code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt(rounds=10)).decode()
        db.execute(
            "INSERT INTO totp_backup_codes (user_id, code_hash) VALUES (?,?)",
            (user_id, code_hash)
        )
        codes.append(code)
    db.commit()
    return codes


@auth_bp.post("/totp/backup-codes/generate")
@require_auth
def generate_backup_codes():
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not user["totp_enabled"]:
        return jsonify({"error": "Enable TOTP first"}), 400
    codes = _generate_backup_codes_for(db, user["id"])
    return jsonify({"codes": codes, "message": "Save these codes securely. Each can only be used once."})


@auth_bp.post("/totp/backup-codes/verify")
def verify_backup_code():
    b     = request.get_json(force=True, silent=True) or {}
    token = b.get("pendingToken")
    code  = (b.get("backupCode") or "").strip().upper().replace(" ", "")

    if not token or not code:
        return jsonify({"error": "Token and backup code required"}), 400

    db      = get_db()
    pending = db.execute("SELECT * FROM pending_challenges WHERE token=?", (token,)).fetchone()
    if not pending:
        return jsonify({"error": "Invalid challenge"}), 400

    user   = db.execute("SELECT * FROM users WHERE id=?", (pending["user_id"],)).fetchone()
    stored = db.execute(
        "SELECT * FROM totp_backup_codes WHERE user_id=? AND used=0", (user["id"],)
    ).fetchall()

    matched = None
    for bc in stored:
        if bcrypt.checkpw(code.encode(), bc["code_hash"].encode()):
            matched = bc
            break

    if not matched:
        return jsonify({"error": "Invalid backup code"}), 401

    db.execute("UPDATE totp_backup_codes SET used=1 WHERE id=?", (matched["id"],))
    db.commit()

    geo = {k: pending[k] for k in ("country", "region", "city", "lat", "lon", "isp", "timezone")}
    _complete_login(user, pending["ip"], geo, pending["device_hash"],
                    pending["risk_score"], pending["risk_tier"],
                    json.loads(pending["risk_reasons"]), ["password", "totp_backup"])
    db.execute("DELETE FROM pending_challenges WHERE token=?", (token,))
    db.commit()
    return jsonify({"status": "authenticated", "warning": "Backup code used — please regenerate new ones."})


@auth_bp.get("/totp/backup-codes/count")
@require_auth
def backup_codes_count():
    db    = get_db()
    total = db.execute(
        "SELECT COUNT(*) as c FROM totp_backup_codes WHERE user_id=? AND used=0",
        (session["user_id"],)
    ).fetchone()["c"]
    return jsonify({"remaining": total})


# ------------------------------------------------------------------
# Password Reset — Step 1
# ------------------------------------------------------------------

@auth_bp.post("/reset-password")
def reset_password_request():
    b     = request.get_json(force=True, silent=True) or {}
    email = (b.get("email") or "").strip()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        return jsonify({"message": "If this email exists a reset code has been sent"}), 200

    code    = str(_secrets_module.randbelow(10**6)).zfill(6)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("UPDATE users SET totp_secret=? WHERE id=?",
               (f"RESET:{code}:{expires}", user["id"]))
    db.commit()

    try:
        _send_reset_email(email, code)
    except Exception as e:
        print(f"[RESET EMAIL ERROR] {e}")
        print(f"[RESET CODE CONSOLE] Code for {email}: {code}")

    return jsonify({"message": "Reset code sent to your email"}), 200


# ------------------------------------------------------------------
# Password Reset — Step 2
# ------------------------------------------------------------------

@auth_bp.post("/reset-password/verify")
def reset_password_verify():
    b     = request.get_json(force=True, silent=True) or {}
    email = (b.get("email") or "").strip()
    code  = (b.get("code")  or "").strip()
    if not email or not code:
        return jsonify({"error": "Email and code are required"}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not user["totp_secret"] or not user["totp_secret"].startswith("RESET:"):
        return jsonify({"error": "Invalid or expired reset code"}), 400

    try:
        parts   = user["totp_secret"].split(":")
        stored  = parts[1]
        expires = ":".join(parts[2:])
        expiry  = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            return jsonify({"error": "Reset code has expired — request a new one"}), 400
        if stored != code:
            return jsonify({"error": "Invalid reset code"}), 400
    except Exception:
        return jsonify({"error": "Invalid or expired reset code"}), 400

    return jsonify({"message": "Code verified"}), 200


# ------------------------------------------------------------------
# Password Reset — Step 3
# ------------------------------------------------------------------

@auth_bp.post("/reset-password/confirm")
def reset_password_confirm():
    b       = request.get_json(force=True, silent=True) or {}
    email   = (b.get("email")        or "").strip()
    code    = (b.get("code")         or "").strip()
    new_pwd = (b.get("new_password") or "")

    if not email or not code or not new_pwd:
        return jsonify({"error": "All fields are required"}), 400

    valid, err = _validate_password(new_pwd)
    if not valid:
        return jsonify({"error": err}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not user["totp_secret"] or not user["totp_secret"].startswith("RESET:"):
        return jsonify({"error": "Invalid or expired reset code"}), 400

    try:
        parts   = user["totp_secret"].split(":")
        stored  = parts[1]
        expires = ":".join(parts[2:])
        expiry  = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            return jsonify({"error": "Reset code has expired — request a new one"}), 400
        if stored != code:
            return jsonify({"error": "Invalid reset code"}), 400
    except Exception:
        return jsonify({"error": "Invalid or expired reset code"}), 400

    new_hash = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt(rounds=12)).decode()
    db.execute(
        "UPDATE users SET password_hash=?, totp_secret=NULL, totp_enabled=0 WHERE id=?",
        (new_hash, user["id"])
    )
    db.commit()
    return jsonify({"message": "Password reset successfully"}), 200


# ------------------------------------------------------------------
# Revoke all sessions via email "Was this you?" link
# ------------------------------------------------------------------

@auth_bp.get("/revoke-alert")
def revoke_alert():
    token = request.args.get("token")
    if not token:
        return "<h2>Invalid link.</h2>", 400
    db    = get_db()
    alert = db.execute(
        "SELECT * FROM security_alerts WHERE token=? AND resolved=0", (token,)
    ).fetchone()
    if not alert:
        return """
        <html><body style="font-family:Arial,sans-serif;text-align:center;padding:60px;background:#0f0c29;color:#fff;">
        <h1 style="color:#fbbf24;">⚠️ Link Expired</h1>
        <p style="color:rgba(255,255,255,0.6);">This link has already been used or has expired.</p>
        <a href="/login.html" style="display:inline-block;margin-top:20px;background:#8b5cf6;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:700;">Go to Login</a>
        </body></html>
        """, 400
    db.execute("UPDATE active_sessions SET is_active=0 WHERE user_id=?", (alert["user_id"],))
    db.execute("UPDATE security_alerts SET resolved=1 WHERE token=?", (token,))
    db.commit()
    return """
    <html><body style="font-family:Arial,sans-serif;text-align:center;padding:60px;background:#0f0c29;color:#fff;">
    <h1 style="color:#f87171;">🚫 All Sessions Revoked</h1>
    <p style="color:rgba(255,255,255,0.6);">All active sessions on your account have been revoked.<br/>
    Please log in again and change your password immediately.</p>
    <a href="/login.html" style="display:inline-block;margin-top:20px;background:#8b5cf6;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:700;">Go to Login</a>
    </body></html>
    """


# ------------------------------------------------------------------
# Session Context — real-time IP, location, ISP, server time
# ------------------------------------------------------------------

def _is_private_ip(ip):
    """Returns True for loopback, link-local, and RFC-1918 private addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


@auth_bp.route('/session-context')
def session_context():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    result = {
        'ip': ip,
        'city': 'Unknown',
        'country': 'Unknown',
        'country_code': '',
        'isp': 'Unknown',
        'server_time': datetime.now().strftime('%A, %d %B %Y - %H:%M:%S'),
    }

    if _is_private_ip(ip):
        result['city']    = 'Local Network'
        result['country'] = 'Local Network'
        result['isp']     = 'Local Network'
        return jsonify(result)

    try:
        import geoip2.database
        with geoip2.database.Reader('GeoLite2-City.mmdb') as r:
            geo = r.city(ip)
            result['city']         = geo.city.name    or 'Unknown'
            result['country']      = geo.country.name or 'Unknown'
            result['country_code'] = geo.country.iso_code or ''
    except Exception:
        pass

    try:
        import geoip2.database
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as r:
            asn = r.asn(ip)
            result['isp'] = asn.autonomous_system_organization or 'Unknown'
    except Exception:
        pass

    return jsonify(result)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _geo_label(geo):
    parts = [p for p in [geo.get("city"), geo.get("country")]
             if p and p not in ("Local Network", "Unknown")]
    return ", ".join(parts) if parts else "Unknown location"


def _log(db, user_id, username, ip, geo, dhash,
         outcome, score=None, tier=None, reasons=None, required_factors=None, auth_method=None):
    db.execute("""
        INSERT INTO login_logs
            (user_id, username_attempted, ip,
             country, region, city, lat, lon, isp, timezone,
             device_hash, risk_score, risk_tier,
             risk_reasons, required_factors, auth_method, outcome)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user_id, username, ip,
        geo.get("country"), geo.get("region"), geo.get("city"),
        geo.get("lat"), geo.get("lon"), geo.get("isp"), geo.get("timezone"),
        dhash, score, tier,
        json.dumps(reasons)          if reasons          is not None else None,
        json.dumps(required_factors) if required_factors is not None else None,
        auth_method,
        outcome,
    ))
    db.commit()


def _complete_login(user, ip, geo, dhash, score, tier, reasons, required_factors):
    db = get_db()
    session["user_id"] = user["id"]
    factor_labels = []
    if "totp_backup" in required_factors:
        factor_labels.append("totp_backup")
    elif "totp" in required_factors:
        factor_labels.append("totp")
    if "sms_otp" in required_factors:
        factor_labels.append("sms_otp")
    if "email_otp" in required_factors:
        factor_labels.append("email_otp")

    if factor_labels:
        auth_method = "password + " + " + ".join(factor_labels)
    else:
        auth_method = "password"

    existing = db.execute(
        "SELECT id FROM known_devices WHERE user_id=? AND device_hash=?",
        (user["id"], dhash)
    ).fetchone()
    device_is_new = existing is None

    db.execute(
        "INSERT OR IGNORE INTO known_devices (user_id, device_hash) VALUES (?,?)",
        (user["id"], dhash)
    )
    db.execute(
        "UPDATE known_devices SET last_seen=datetime('now') WHERE user_id=? AND device_hash=?",
        (user["id"], dhash)
    )

    sess_uuid  = str(uuid.uuid4())
    session["session_uuid"] = sess_uuid
    user_agent = request.headers.get("User-Agent", "Unknown")[:300]
    db.execute("""
        INSERT INTO active_sessions
            (session_uuid, user_id, ip, country, city, isp, device_hash, user_agent)
        VALUES (?,?,?,?,?,?,?,?)
    """, (sess_uuid, user["id"], ip, geo.get("country"), geo.get("city"),
          geo.get("isp"), dhash, user_agent))

    _log(db, user["id"], user["username"], ip, geo, dhash,
         outcome="success",
         score=score or 0, tier=tier or "LOW",
         reasons=reasons or [], required_factors=required_factors or ["password"],
         auth_method=auth_method)
    db.commit()

    try:
        alert_token = str(uuid.uuid4())
        db.execute("""
            INSERT INTO security_alerts (token, user_id, ip, country, city)
            VALUES (?,?,?,?,?)
        """, (alert_token, user["id"], ip, geo.get("country"), geo.get("city")))
        db.commit()
        threading.Thread(
            target=_send_login_alert_email,
            args=(user["email"], user["username"], ip,
                  geo.get("city"), geo.get("country"),
                  device_is_new, alert_token),
            daemon=True
        ).start()
    except Exception as e:
        print(f"[LOGIN ALERT ERROR] {e}")