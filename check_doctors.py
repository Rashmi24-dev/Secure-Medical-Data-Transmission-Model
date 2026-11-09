import sqlite3

conn = sqlite3.connect("medical.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM doctors")
rows = cursor.fetchall()

print("Total Doctors:", len(rows))

for row in rows:
    print(row)

conn.close()