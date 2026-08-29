"""routes/sus.py — Usability questionnaire. Higher always = better."""
import json
from flask import Blueprint, jsonify, request, session
from db import get_db

sus_bp = Blueprint("sus", __name__, url_prefix="/api/sus")

@sus_bp.post("/submit")
def submit():
    b           = request.get_json(force=True, silent=True) or {}
    answers     = b.get("answers", [])
    participant = (b.get("participant") or "Anonymous").strip()
    suggestions = (b.get("suggestions") or "").strip()
    if len(answers) != 10:
        return jsonify({"error":"Exactly 10 answers required."}), 400
    try:
        answers = [int(a) for a in answers]
        if not all(1 <= a <= 5 for a in answers): raise ValueError()
    except (ValueError,TypeError):
        return jsonify({"error":"Each answer must be 1-5."}), 400
    raw_score   = sum(answers)
    total_score = round((raw_score / 50) * 100, 1)
    db = get_db()
    db.execute("INSERT INTO sus_responses (user_id,participant,answers,raw_score,total_score,suggestions) VALUES (?,?,?,?,?,?)",
               (session.get("user_id"),participant,json.dumps(answers),raw_score,total_score,suggestions or None))
    db.commit()
    return jsonify({"message":"Response saved.","raw_score":raw_score,"total_score":total_score,"grade":_grade(total_score)}), 201

@sus_bp.get("/results")
def results():
    db   = get_db()
    rows = db.execute("SELECT id,participant,answers,raw_score,total_score,suggestions,submitted_at FROM sus_responses ORDER BY submitted_at DESC").fetchall()
    responses = [{"id":r["id"],"participant":r["participant"],"answers":json.loads(r["answers"]),"raw_score":r["raw_score"],"total_score":r["total_score"],"grade":_grade(r["total_score"]),"suggestions":r["suggestions"],"submitted_at":r["submitted_at"]} for r in rows]
    scores = [r["total_score"] for r in responses]
    return jsonify({"responses":responses,"summary":{"count":len(scores),"average":round(sum(scores)/len(scores),1) if scores else None,"min":min(scores) if scores else None,"max":max(scores) if scores else None}})

def _grade(score):
    if score >= 80: return "Excellent"
    if score >= 60: return "Good"
    if score >= 40: return "Fair"
    return "Poor"