import sqlite3, glob

dbs = glob.glob("*.db") + glob.glob("**/*.db", recursive=True)
if not dbs:
    print("ERROR: No .db file found.")
    exit(1)

db_path = dbs[0]
print("Migrating:", db_path)
conn = sqlite3.connect(db_path)
c = conn.cursor()

def run(sql, label):
    try:
        c.execute(sql)
        print("  OK:", label)
    except Exception as e:
        if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
            print("  SKIP:", label)
        else:
            print("  ERROR:", label, e)

run("ALTER TABLE login_logs ADD COLUMN auth_method TEXT", "login_logs.auth_method")
run("ALTER TABLE known_devices ADD COLUMN login_count INTEGER DEFAULT 1", "known_devices.login_count")
run("""CREATE TABLE IF NOT EXISTS active_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uuid TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT, country TEXT, city TEXT, isp TEXT,
    device_hash TEXT, user_agent TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_active TEXT DEFAULT (datetime('now')),
    is_active INTEGER DEFAULT 1)""", "active_sessions")
run("""CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL, used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')))""", "totp_backup_codes")
run("""CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT, country TEXT, city TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    resolved INTEGER DEFAULT 0)""", "security_alerts")

conn.commit()
conn.close()
print("Done! Restart Flask.")
