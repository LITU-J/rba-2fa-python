from app import app
from db import get_db

with app.app_context():
    db = get_db()
    db.execute("UPDATE users SET is_admin=1 WHERE username='Muna'")
    db.commit()
    row = db.execute("SELECT id, username, is_admin FROM users WHERE username='Muna'").fetchone()
    if row:
        print(f"Done — {row['username']} is_admin={row['is_admin']}")
    else:
        print("User 'Muna' not found — please register first, then run this script again.")