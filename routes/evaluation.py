"""routes/evaluation.py — FAR, FRR, TPR, EER metrics for Research Objective 3."""
import json
from flask import Blueprint, jsonify
from db import get_db
from routes.auth import require_auth

evaluation_bp = Blueprint("evaluation", __name__, url_prefix="/api/evaluation")

@evaluation_bp.get("/metrics")
@require_auth
def metrics():
    db = get_db()
    total_attacks = db.execute("SELECT COUNT(*) AS c FROM login_logs WHERE simulated_attack_type IS NOT NULL").fetchone()["c"]
    total_legit   = db.execute("SELECT COUNT(*) AS c FROM login_logs WHERE simulated_attack_type IS NULL AND user_id IS NOT NULL").fetchone()["c"]
    false_acc     = db.execute("SELECT COUNT(*) AS c FROM login_logs WHERE simulated_attack_type IS NOT NULL AND risk_tier='LOW' AND outcome='success'").fetchone()["c"]
    false_rej     = db.execute("SELECT COUNT(*) AS c FROM login_logs WHERE simulated_attack_type IS NULL AND outcome='blocked'").fetchone()["c"]
    true_pos      = db.execute("SELECT COUNT(*) AS c FROM login_logs WHERE simulated_attack_type IS NOT NULL AND risk_tier IN ('MEDIUM','HIGH','CRITICAL')").fetchone()["c"]
    far = round((false_acc/total_attacks*100) if total_attacks else 0, 2)
    frr = round((false_rej/total_legit*100)   if total_legit   else 0, 2)
    tpr = round((true_pos/total_attacks*100)  if total_attacks else 0, 2)
    eer = round((far+frr)/2, 2)
    tier_rows = db.execute("SELECT risk_tier,COUNT(*) AS c FROM login_logs WHERE risk_tier IS NOT NULL GROUP BY risk_tier").fetchall()
    tier_dist = {r["risk_tier"]:r["c"] for r in tier_rows}
    attack_rows = db.execute("SELECT simulated_attack_type AS atype,risk_tier,outcome,COUNT(*) AS c FROM login_logs WHERE simulated_attack_type IS NOT NULL GROUP BY simulated_attack_type,risk_tier,outcome").fetchall()
    attack_breakdown = {}
    for r in attack_rows:
        a = r["atype"]
        if a not in attack_breakdown: attack_breakdown[a]={"total":0,"blocked":0,"escalated":0,"accepted":0}
        attack_breakdown[a]["total"] += r["c"]
        if r["risk_tier"]=="CRITICAL": attack_breakdown[a]["blocked"]   += r["c"]
        elif r["risk_tier"] in ("MEDIUM","HIGH"): attack_breakdown[a]["escalated"] += r["c"]
        else: attack_breakdown[a]["accepted"] += r["c"]
    reason_rows = db.execute("SELECT risk_reasons FROM login_logs WHERE risk_reasons IS NOT NULL AND risk_reasons!='[]'").fetchall()
    indicator_counts = {}
    for row in reason_rows:
        try:
            for reason in json.loads(row["risk_reasons"]):
                key = reason.split("(+")[0].strip()
                indicator_counts[key] = indicator_counts.get(key,0)+1
        except Exception: pass
    indicator_counts = dict(sorted(indicator_counts.items(),key=lambda x:x[1],reverse=True))
    sus_summary = {"count":0,"average":None,"min":None,"max":None}
    try:
        s = db.execute("SELECT COUNT(*) AS cnt,AVG(total_score) AS avg,MIN(total_score) AS mn,MAX(total_score) AS mx FROM sus_responses").fetchone()
        if s and s["cnt"]: sus_summary={"count":s["cnt"],"average":round(s["avg"],1),"min":s["mn"],"max":s["mx"]}
    except Exception: pass
    outcome_rows = db.execute("SELECT outcome,COUNT(*) AS c FROM login_logs GROUP BY outcome").fetchall()
    return jsonify({"totals":{"attacks":total_attacks,"legitimate":total_legit,"false_acceptances":false_acc,"false_rejections":false_rej,"true_positives":true_pos},"rates":{"FAR":far,"FRR":frr,"TPR":tpr,"EER":eer},"tier_distribution":tier_dist,"attack_breakdown":attack_breakdown,"indicator_frequency":indicator_counts,"sus_summary":sus_summary,"outcomes":{r["outcome"]:r["c"] for r in outcome_rows}})