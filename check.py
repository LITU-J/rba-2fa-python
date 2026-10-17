import sqlite3
db = sqlite3.connect('data/app.sqlite')
tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print('Tables:', tables)
db.close()