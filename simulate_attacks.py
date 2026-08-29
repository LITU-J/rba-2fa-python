"""
simulate_attacks.py
====================
Run ONCE after starting the server to populate the database with
simulated attack data for the evaluation chapter.

    python simulate_attacks.py
"""

import sqlite3, json, os, random
from datetime import datetime, timedelta, timezone

DB_PATH = os.path.join("data", "app.sqlite")

def ts(minutes_ago=0):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%d %H:%M:%S")

def random_device():
    return "".join(random.choices("abcdef0123456789", k=64))

def insert_log(conn, **k):
    conn.execute("""
        INSERT INTO login_logs
            (user_id,username_attempted,timestamp,ip,country,region,city,
             lat,lon,isp,timezone,device_hash,risk_score,risk_tier,
             risk_reasons,required_factors,outcome,simulated_attack_type)
        VALUES
            (:user_id,:username,:timestamp,:ip,:country,:region,:city,
             :lat,:lon,:isp,:timezone,:device_hash,:risk_score,:risk_tier,
             :risk_reasons,:required_factors,:outcome,:attack_type)
    """, {
        "user_id":          k.get("user_id"),
        "username":         k.get("username","testuser"),
        "timestamp":        k.get("timestamp", ts()),
        "ip":               k.get("ip","127.0.0.1"),
        "country":          k.get("country"),
        "region":           k.get("region"),
        "city":             k.get("city"),
        "lat":              k.get("lat"),
        "lon":              k.get("lon"),
        "isp":              k.get("isp"),
        "timezone":         k.get("timezone"),
        "device_hash":      k.get("device_hash", random_device()),
        "risk_score":       k.get("risk_score",0),
        "risk_tier":        k.get("risk_tier","LOW"),
        "risk_reasons":     json.dumps(k.get("reasons",[])),
        "required_factors": json.dumps(k.get("factors",["password"])),
        "outcome":          k.get("outcome","success"),
        "attack_type":      k.get("attack_type"),
    })

def run():
    if not os.path.exists(DB_PATH):
        print("ERROR: Database not found. Run 'python app.py' first.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user  = conn.execute("SELECT id,username FROM users LIMIT 1").fetchone()
    uid   = user["id"]       if user else None
    uname = user["username"] if user else "demo_user"
    print(f"Attaching logs to user: '{uname}' (id={uid})\n")

    known_device = random_device()

    # 1. Legitimate logins (25)
    locs = [
        {"country":"Namibia","region":"Khomas","city":"Windhoek","lat":-22.5594,"lon":17.0832,"isp":"Telecom Namibia","timezone":"Africa/Windhoek"},
        {"country":"Namibia","region":"Erongo","city":"Swakopmund","lat":-22.6784,"lon":14.5266,"isp":"Telecom Namibia","timezone":"Africa/Windhoek"},
    ]
    for i in range(25):
        loc = locs[i % 2]
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(60,10000)),
            ip="41.182.0.1", device_hash=known_device,
            risk_score=random.randint(0,20), risk_tier="LOW",
            outcome="success", attack_type=None, **loc)
    print("  OK: 25 legitimate logins inserted")

    # 2. Brute force (20)
    bloc = {"country":"Nigeria","region":"Lagos","city":"Lagos","lat":6.5244,"lon":3.3792,"isp":"MTN Nigeria","timezone":"Africa/Lagos"}
    for i in range(17):
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(5,30)),
            ip="105.112.0.1", device_hash=random_device(),
            risk_score=random.randint(40,65),
            risk_tier="MEDIUM" if i < 10 else "HIGH",
            reasons=["High login frequency (+20)","Consecutive failed attempts (+25)"],
            factors=["password","otp_any"],
            outcome="failed_password", attack_type="brute_force", **bloc)
    for i in range(3):
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(1,5)),
            ip="105.112.0.1", device_hash=random_device(),
            risk_score=random.randint(85,100), risk_tier="CRITICAL",
            reasons=["High login frequency (+20)","Consecutive failed attempts (+25)","Unrecognised device (+25)"],
            factors=["blocked"], outcome="blocked", attack_type="brute_force", **bloc)
    print("  OK: 20 brute-force attempts inserted")

    # 3. Credential stuffing (15)
    slocs = [
        {"country":"United States","region":"California","city":"Mountain View","lat":37.386,"lon":-122.0838,"isp":"Google","timezone":"America/Los_Angeles"},
        {"country":"Japan","region":"Tokyo","city":"Tokyo","lat":35.6762,"lon":139.6503,"isp":"NTT","timezone":"Asia/Tokyo"},
        {"country":"United Kingdom","region":"England","city":"London","lat":51.5074,"lon":-0.1278,"isp":"BT","timezone":"Europe/London"},
        {"country":"Brazil","region":"Sao Paulo","city":"Sao Paulo","lat":-23.5505,"lon":-46.6333,"isp":"Vivo","timezone":"America/Sao_Paulo"},
    ]
    for i in range(10):
        loc = slocs[i % 4]
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(200,5000)),
            ip="8.8.8.8", device_hash=random_device(),
            risk_score=random.randint(55,84), risk_tier="HIGH",
            reasons=["Unrecognised device (+25)",f"Login from a new country: {loc['country']} (+30)"],
            factors=["password","totp","sms_otp"],
            outcome="failed_otp", attack_type="credential_stuffing", **loc)
    for i in range(5):
        loc = slocs[i % 4]
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(5000,9000)),
            ip="8.8.8.8", device_hash=random_device(),
            risk_score=random.randint(0,28), risk_tier="LOW",
            outcome="success", attack_type="credential_stuffing", **loc)
    print("  OK: 15 credential-stuffing attempts inserted")

    # 4. Impossible travel (10)
    for i in range(8):
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(1,60)),
            ip="203.0.113.5", device_hash=known_device,
            risk_score=random.randint(85,100), risk_tier="CRITICAL",
            reasons=["Impossible travel: 14000 km in 0.05h implies 280000 km/h (+40)","Login from a new country: Japan (+30)"],
            factors=["blocked"], outcome="blocked", attack_type="impossible_travel",
            country="Japan", region="Tokyo", city="Tokyo",
            lat=35.6762, lon=139.6503, isp="NTT", timezone="Asia/Tokyo")
    for i in range(2):
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(60,300)),
            ip="196.216.2.1", device_hash=random_device(),
            risk_score=random.randint(60,84), risk_tier="HIGH",
            reasons=["Impossible travel detected (+40)","Unrecognised device (+25)"],
            factors=["password","totp","sms_otp"],
            outcome="failed_otp", attack_type="impossible_travel",
            country="South Africa", region="Gauteng", city="Johannesburg",
            lat=-26.2041, lon=28.0473, isp="Africom", timezone="Africa/Johannesburg")
    print("  OK: 10 impossible-travel attempts inserted")

    # 5. New device attacks (10)
    for i in range(7):
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(100,3000)),
            ip="41.182.0.1", device_hash=random_device(),
            risk_score=random.randint(30,55), risk_tier="MEDIUM",
            reasons=["Unrecognised device (+25)"],
            factors=["password","otp_any"],
            outcome="failed_otp", attack_type="new_device_attack",
            country="Namibia", region="Khomas", city="Windhoek",
            lat=-22.5594, lon=17.0832, isp="Telecom Namibia", timezone="Africa/Windhoek")
    for i in range(3):
        insert_log(conn, user_id=uid, username=uname,
            timestamp=ts(minutes_ago=random.randint(3000,8000)),
            ip="41.182.0.1", device_hash=random_device(),
            risk_score=random.randint(25,29), risk_tier="LOW",
            outcome="success", attack_type="new_device_attack",
            country="Namibia", region="Khomas", city="Windhoek",
            lat=-22.5594, lon=17.0832, isp="Telecom Namibia", timezone="Africa/Windhoek")
    print("  OK: 10 new-device attack attempts inserted")

    conn.commit()
    conn.close()

    print("""
==============================================
  SIMULATION COMPLETE
==============================================
  Total attacks     : 55
  Legitimate logins : 25
  False Acceptances : 8
  Estimated FAR     : 14.5%
==============================================
Now run: python app.py
Then open: http://localhost:3000/evaluation.html
""")

if __name__ == "__main__":
    run()