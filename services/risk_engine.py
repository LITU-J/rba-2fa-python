"""
services/risk_engine.py
========================
Weighted Risk-Scoring Engine — Research Objective 2.
Evaluates 7 contextual indicators for every login attempt.

Indicators:
  1. New country        — foreign country login           (+65)
  2. New city           — different city same country     (+30)
  3. New device         — unrecognised device             (+25)
  4. Unusual time       — unusual login hour              (+10)
  5. High frequency     — too many attempts               (+20)
  6. Consecutive fails  — brute-force pattern             (+25)
  7. Impossible travel  — distance over 1000km at
                          impossible speed → CRITICAL
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

    # Fetch successful login history as baseline
    history = db.execute(
        "SELECT * FROM login_logs WHERE user_id=? AND outcome='success' "
        "ORDER BY timestamp DESC LIMIT 50",
        (user_id,)).fetchall()

    # ------------------------------------------------------------------
    # HARD BLOCK: 5 consecutive failures = instant CRITICAL block
    # ------------------------------------------------------------------
    recent = db.execute(
        "SELECT outcome FROM login_logs WHERE user_id=? "
        "ORDER BY timestamp DESC LIMIT ?",
        (user_id, config.HARD_BLOCK_AFTER_FAILURES)).fetchall()

    if (len(recent) >= config.HARD_BLOCK_AFTER_FAILURES
            and all(r["outcome"] and r["outcome"].startswith("failed")
                    for r in recent)):
        return {
            "score":   100,
            "tier":    "CRITICAL",
            "reasons": [
                f"Account locked: {config.HARD_BLOCK_AFTER_FAILURES} "
                f"consecutive failed attempts — brute-force attack (+100)"
            ],
        }

    # ------------------------------------------------------------------
    # Indicator 1: New country (+65 → HIGH immediately on its own)
    # ------------------------------------------------------------------
    if geo["country"] and len(history) > 0:
        known_countries = [r["country"] for r in history if r["country"]]
        if known_countries and geo["country"] not in known_countries:
            pts = config.RISK_WEIGHTS["new_country"]
            score += pts
            reasons.append(
                f"Login from a new country: {geo['country']} (+{pts})"
            )

    # ------------------------------------------------------------------
    # Indicator 2: New city same country (+30 → MEDIUM on its own)
    # Only fires when country is already known — avoids double penalty
    # ------------------------------------------------------------------
    if geo["country"] and geo["city"] and geo["city"] not in ("Local Network", "Unknown"):
        known_countries = [r["country"] for r in history if r["country"]]
        if geo["country"] in known_countries:
            known_cities = [
                r["city"] for r in history
                if r["country"] == geo["country"] and r["city"]
            ]
            if known_cities and geo["city"] not in known_cities:
                pts = config.RISK_WEIGHTS["new_city"]
                score += pts
                reasons.append(
                    f"Login from a new city within {geo['country']}: "
                    f"{geo['city']} (+{pts})"
                )

    # ------------------------------------------------------------------
    # Indicator 3: New device (+25)
    # ------------------------------------------------------------------
    if not db.execute(
        "SELECT 1 FROM known_devices WHERE user_id=? AND device_hash=?",
        (user_id, device_hash)
    ).fetchone():
        pts = config.RISK_WEIGHTS["new_device"]
        score += pts
        reasons.append(f"Unrecognised device (+{pts})")

    # ------------------------------------------------------------------
    # Indicator 4: Unusual login time (+10)
    # ------------------------------------------------------------------
    if len(history) >= 3:
        current_hour = now.hour
        smallest_gap = min(
            min(
                abs(_parse_ts(r["timestamp"]).hour - current_hour),
                24 - abs(_parse_ts(r["timestamp"]).hour - current_hour)
            )
            for r in history
        )
        if smallest_gap > 5:
            pts = config.RISK_WEIGHTS["unusual_time"]
            score += pts
            reasons.append(
                f"Unusual login time ({current_hour}:00 UTC) (+{pts})"
            )

    # ------------------------------------------------------------------
    # Indicator 5: High login frequency (+20)
    # ------------------------------------------------------------------
    window_start = (
        now - timedelta(minutes=config.FREQUENCY_WINDOW_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")

    count = db.execute(
        "SELECT COUNT(*) AS c FROM login_logs "
        "WHERE user_id=? AND timestamp>=?",
        (user_id, window_start)
    ).fetchone()["c"]

    if count >= config.FREQUENCY_MAX_ATTEMPTS:
        pts = config.RISK_WEIGHTS["high_frequency"]
        score += pts
        reasons.append(
            f"High login frequency: {count} attempts in "
            f"{config.FREQUENCY_WINDOW_MINUTES} min (+{pts})"
        )

    # ------------------------------------------------------------------
    # Indicator 6: Consecutive failures (+25)
    # ------------------------------------------------------------------
    consec = db.execute(
        "SELECT outcome FROM login_logs WHERE user_id=? "
        "ORDER BY timestamp DESC LIMIT ?",
        (user_id, config.CONSECUTIVE_FAILURE_THRESHOLD)
    ).fetchall()

    if (len(consec) >= config.CONSECUTIVE_FAILURE_THRESHOLD
            and all(r["outcome"] and r["outcome"].startswith("failed")
                    for r in consec)):
        pts = config.RISK_WEIGHTS["consecutive_failures"]
        score += pts
        reasons.append(
            f"{config.CONSECUTIVE_FAILURE_THRESHOLD} consecutive "
            f"failed attempts (+{pts})"
        )

    # ------------------------------------------------------------------
    # Indicator 7: Geo-velocity — impossible travel
    #
    # Returns CRITICAL immediately when triggered.
    # Minimum distance is 1000 km to avoid flagging domestic city
    # changes like Windhoek to Swakopmund (263 km) as impossible travel.
    # Those are correctly handled by Indicator 2 (new city).
    # ------------------------------------------------------------------
    if geo["lat"] is not None and geo["lon"] is not None:

        last_with_geo = next(
            (r for r in history
             if r["lat"] is not None and r["lon"] is not None),
            None
        )

        if last_with_geo:
            hours = max(
                (now - _parse_ts(last_with_geo["timestamp"])
                 ).total_seconds() / 3600,
                0.01
            )
            dist_km = haversine_distance_km(
                last_with_geo["lat"], last_with_geo["lon"],
                geo["lat"], geo["lon"]
            )
            speed = dist_km / hours

            print(f"[GEO-VELOCITY] Distance: {round(dist_km)} km | "
                  f"Time: {hours:.4f}h | Speed: {round(speed)} km/h")

            if dist_km > 5000 and speed > config.IMPOSSIBLE_TRAVEL_SPEED_KMH:
                return {
                    "score":   100,
                    "tier":    "CRITICAL",
                    "reasons": reasons + [
                        f"Impossible travel: {round(dist_km)} km in "
                        f"{hours:.2f}h implies {round(speed)} km/h "
                        f"— access blocked (+100)"
                    ],
                }

    # ------------------------------------------------------------------
    # Final score and tier
    # ------------------------------------------------------------------
    final = min(score, 100)
    return {
        "score":   final,
        "tier":    score_to_tier(final),
        "reasons": reasons,
    }


def score_to_tier(score):
    if score <= config.RISK_TIERS["LOW"]["max_score"]:    return "LOW"
    if score <= config.RISK_TIERS["MEDIUM"]["max_score"]: return "MEDIUM"
    if score <= config.RISK_TIERS["HIGH"]["max_score"]:   return "HIGH"
    return "CRITICAL"


def required_factors_for_tier(tier):
    return config.RISK_TIERS[tier]["requires"]