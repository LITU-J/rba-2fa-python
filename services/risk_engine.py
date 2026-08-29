"""
services/risk_engine.py — Weighted Risk-Scoring Engine (Research Objective 2).
Evaluates 7 contextual indicators for every login attempt.
"""

from datetime import datetime, timedelta, timezone
import config
from db import get_db
from services.geo_service import haversine_distance_km


def _parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def assess_risk(user_id, device_hash, geo, now=None):
    db  = get_db()
    now = now or datetime.now(timezone.utc)
    score, reasons = 0, []

    history = db.execute(
        "SELECT * FROM login_logs WHERE user_id=? AND outcome='success' ORDER BY timestamp DESC LIMIT 20",
        (user_id,)).fetchall()

    # Hard block check
    recent = db.execute(
        "SELECT outcome FROM login_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
        (user_id, config.HARD_BLOCK_AFTER_FAILURES)).fetchall()
    if (len(recent) >= config.HARD_BLOCK_AFTER_FAILURES
            and all(r["outcome"] and r["outcome"].startswith("failed") for r in recent)):
        return {"score":100,"tier":"CRITICAL","reasons":[f"Account locked: {config.HARD_BLOCK_AFTER_FAILURES} consecutive failed attempts (+100)"]}

    # Indicator 1: New country
    if geo["country"] and len(history) > 0:
        known = [r["country"] for r in history if r["country"]]
        if geo["country"] not in known:
            pts = config.RISK_WEIGHTS["new_country"]
            score += pts
            reasons.append(f"Login from a new country: {geo['country']} (+{pts})")

    # Indicator 2: New city (same country)
    if geo["country"] and geo["city"] and geo["city"] not in ("Local Network","Unknown"):
        known_countries = [r["country"] for r in history if r["country"]]
        if geo["country"] in known_countries:
            known_cities = [r["city"] for r in history if r["country"]==geo["country"] and r["city"]]
            if geo["city"] not in known_cities and len(known_cities) > 0:
                pts = config.RISK_WEIGHTS["new_city"]
                score += pts
                reasons.append(f"Login from a new city within {geo['country']}: {geo['city']} (+{pts})")

    # Indicator 3: New device
    if not db.execute("SELECT 1 FROM known_devices WHERE user_id=? AND device_hash=?",(user_id,device_hash)).fetchone():
        pts = config.RISK_WEIGHTS["new_device"]
        score += pts
        reasons.append(f"Unrecognised device (+{pts})")

    # Indicator 4: Unusual login time
    if len(history) >= 3:
        current_hour = now.hour
        smallest_gap = min(min(abs(_parse_ts(r["timestamp"]).hour - current_hour),
                               24 - abs(_parse_ts(r["timestamp"]).hour - current_hour)) for r in history)
        if smallest_gap > 5:
            pts = config.RISK_WEIGHTS["unusual_time"]
            score += pts
            reasons.append(f"Unusual login time ({current_hour}:00 UTC) (+{pts})")

    # Indicator 5: High frequency
    window_start = (now - timedelta(minutes=config.FREQUENCY_WINDOW_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    count = db.execute("SELECT COUNT(*) AS c FROM login_logs WHERE user_id=? AND timestamp>=?",(user_id,window_start)).fetchone()["c"]
    if count >= config.FREQUENCY_MAX_ATTEMPTS:
        pts = config.RISK_WEIGHTS["high_frequency"]
        score += pts
        reasons.append(f"High login frequency: {count} attempts in {config.FREQUENCY_WINDOW_MINUTES} min (+{pts})")

    # Indicator 6: Consecutive failures
    consec = db.execute("SELECT outcome FROM login_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",(user_id,config.CONSECUTIVE_FAILURE_THRESHOLD)).fetchall()
    if (len(consec) >= config.CONSECUTIVE_FAILURE_THRESHOLD
            and all(r["outcome"] and r["outcome"].startswith("failed") for r in consec)):
        pts = config.RISK_WEIGHTS["consecutive_failures"]
        score += pts
        reasons.append(f"{config.CONSECUTIVE_FAILURE_THRESHOLD} consecutive failed attempts (+{pts})")

    # Indicator 7: Geo-velocity
    last = history[0] if history else None
    if (last and last["lat"] is not None and last["lon"] is not None
            and geo["lat"] is not None and geo["lon"] is not None):
        hours   = max((now - _parse_ts(last["timestamp"])).total_seconds()/3600, 0.01)
        dist_km = haversine_distance_km(last["lat"],last["lon"],geo["lat"],geo["lon"])
        speed   = dist_km / hours
        if speed > config.IMPOSSIBLE_TRAVEL_SPEED_KMH:
            pts = config.RISK_WEIGHTS["impossible_travel"]
            score += pts
            reasons.append(f"Impossible travel: {round(dist_km)} km in {hours:.2f}h = {round(speed)} km/h (+{pts})")

    final = min(score, 100)
    return {"score":final,"tier":score_to_tier(final),"reasons":reasons}


def score_to_tier(score):
    if score <= config.RISK_TIERS["LOW"]["max_score"]:    return "LOW"
    if score <= config.RISK_TIERS["MEDIUM"]["max_score"]: return "MEDIUM"
    if score <= config.RISK_TIERS["HIGH"]["max_score"]:   return "HIGH"
    return "CRITICAL"

def required_factors_for_tier(tier):
    return config.RISK_TIERS[tier]["requires"]