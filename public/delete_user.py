from app import app
from db import get_db

TARGET = "Litu"

with app.app_context():
    db = get_db()

    row = db.execute("SELECT id, username, is_admin FROM users WHERE username=?", (TARGET,)).fetchone()
    if not row:
        print(f"User '{TARGET}' not found in the database.")
    elif row["is_admin"]:
        print(f"Safety stop: '{TARGET}' is an admin — not deleting.")
    else:
        db.execute("DELETE FROM login_logs WHERE user_id=?", (row["id"],))
        db.execute("DELETE FROM pending_challenges WHERE user_id=?", (row["id"],))
        db.execute("DELETE FROM users WHERE id=?", (row["id"],))
        db.commit()
        print(f"Done — user '{TARGET}' (id={row['id']}) has been deleted.")

    print("\nRemaining users:")
    for u in db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall():
        role = " [ADMIN]" if u["is_admin"] else ""
        print(f"  id={u['id']}  {u['username']}{role}")