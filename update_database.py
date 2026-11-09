import sqlite3

# Connect to existing database
conn = sqlite3.connect("medical.db")
cursor = conn.cursor()

try:
    cursor.execute("""
        ALTER TABLE reports
        ADD COLUMN encrypted_aes_key TEXT
    """)

    print("✅ encrypted_aes_key column added successfully!")

except sqlite3.OperationalError as e:

    if "duplicate column name" in str(e).lower():
        print("ℹ️ encrypted_aes_key column already exists.")
    else:
        print("❌ Database error:", e)

conn.commit()
conn.close()

print("✅ Database update completed!")