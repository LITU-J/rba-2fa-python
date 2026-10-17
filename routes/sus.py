"""routes/sus.py — Usability questionnaire. Higher always = better."""
import json
from flask import Blueprint, jsonify, request, session
from db import get_db

sus_bp = Blueprint("sus", __name__, url_prefix="/api/sus")


def _grade(score):
    if score >= 80: return "Excellent"
    if score >= 60: return "Good"
    if score >= 40: return "Fair"
    return "Poor"


def _require_admin():
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
    if not user["is_admin"]:
        return None, (jsonify({"error": "Access denied — admin only"}), 403)
    return user, None


# ── GET /api/sus/status ───────────────────────────────────────────────────────
@sus_bp.get("/status")
def status():
    """Check server-side if the current user already submitted — replaces localStorage."""
    uid = session.get("user_id")
    if not uid:
        return jsonify({"submitted": False})
    db  = get_db()
    row = db.execute(
        "SELECT id FROM sus_responses WHERE user_id=?", (uid,)
    ).fetchone()
    return jsonify({"submitted": bool(row)})


# ── POST /api/sus/submit ──────────────────────────────────────────────────────
@sus_bp.post("/submit")
def submit():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not authenticated"}), 401

    b           = request.get_json(force=True, silent=True) or {}
    answers     = b.get("answers", [])
    participant = (b.get("participant") or "Anonymous").strip()
    suggestions = (b.get("suggestions") or "").strip()

    if len(answers) != 10:
        return jsonify({"error": "Exactly 10 answers required."}), 400
    try:
        answers = [int(a) for a in answers]
        if not all(1 <= a <= 5 for a in answers):
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify({"error": "Each answer must be 1-5."}), 400

    db = get_db()

    # Block duplicate submissions — one per user, tracked in DB not localStorage
    existing = db.execute(
        "SELECT id FROM sus_responses WHERE user_id=?", (uid,)
    ).fetchone()
    if existing:
        return jsonify({"error": "You have already submitted the survey."}), 409

    raw_score   = sum(answers)
    total_score = round((raw_score / 50) * 100, 1)

    db.execute(
        "INSERT INTO sus_responses (user_id, participant, answers, raw_score, total_score, suggestions) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (uid, participant, json.dumps(answers), raw_score, total_score, suggestions or None)
    )
    db.commit()
    return jsonify({
        "message": "Response saved.",
        "raw_score": raw_score,
        "total_score": total_score,
        "grade": _grade(total_score)
    }), 201


# ── GET /api/sus/results  (admin only) ───────────────────────────────────────
@sus_bp.get("/results")
def results():
    """Admin-only: view all submitted survey responses."""
    _, err = _require_admin()
    if err: return err

    db   = get_db()
    rows = db.execute("""
        SELECT sr.id, sr.participant, sr.answers, sr.raw_score,
               sr.total_score, sr.suggestions, sr.submitted_at,
               u.username
        FROM sus_responses sr
        LEFT JOIN users u ON u.id = sr.user_id
        ORDER BY sr.submitted_at DESC
    """).fetchall()

    responses = [{
        "id":           r["id"],
        "participant":  r["participant"],
        "username":     r["username"],
        "answers":      json.loads(r["answers"]),
        "raw_score":    r["raw_score"],
        "total_score":  r["total_score"],
        "grade":        _grade(r["total_score"]),
        "suggestions":  r["suggestions"],
        "submitted_at": r["submitted_at"]
    } for r in rows]

    scores = [r["total_score"] for r in responses]
    return jsonify({
        "responses": responses,
        "summary": {
            "count":   len(scores),
            "average": round(sum(scores) / len(scores), 1) if scores else None,
            "min":     min(scores) if scores else None,
            "max":     max(scores) if scores else None,
        }
    })