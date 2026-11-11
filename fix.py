import sqlite3
conn = sqlite3.connect('data/app.sqlite')
conn.execute("UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL")
conn.commit()
conn.close()
print("Done")