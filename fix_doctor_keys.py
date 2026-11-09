import sqlite3
from security.rsa_keys import generate_keys

conn = sqlite3.connect("medical.db")
cursor = conn.cursor()

# Get doctors who don't have RSA keys
doctors = cursor.execute("""
    SELECT doctor_id, doctor_name
    FROM doctors
    WHERE public_key IS NULL
       OR public_key = ''
       OR private_key IS NULL
       OR private_key = ''
""").fetchall()

if not doctors:
    print("✅ All doctors already have RSA keys.")

else:
    for doctor_id, doctor_name in doctors:

        print(f"Generating RSA keys for Dr. {doctor_name}...")

        private_key, public_key = generate_keys()

        private_key_text = private_key.decode("utf-8")
        public_key_text = public_key.decode("utf-8")

        cursor.execute("""
            UPDATE doctors
            SET
                public_key = ?,
                private_key = ?
            WHERE doctor_id = ?
        """, (
            public_key_text,
            private_key_text,
            doctor_id
        ))

        print(f"✅ RSA keys generated for Dr. {doctor_name}")

    conn.commit()

conn.close()

print()
print("======================================")
print("✅ RSA KEY FIX COMPLETED")
print("======================================")