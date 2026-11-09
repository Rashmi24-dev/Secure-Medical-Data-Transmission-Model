import sqlite3


def create_database():
    conn = sqlite3.connect("medical.db")
    cursor = conn.cursor()

    # ================= HOSPITAL TABLE =================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hospitals (
        hospital_id INTEGER PRIMARY KEY AUTOINCREMENT,
        hospital_name TEXT NOT NULL,
        registration_id TEXT,
        email TEXT,
        phone TEXT,
        location TEXT,
        address TEXT,
        specialization TEXT
    )
    """)

    # ================= ADMIN TABLE =================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        email TEXT
    )
    """)

    # ================= DOCTOR TABLE (UPDATED WITH profile_pic) =================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS doctors (
        doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        hospital_id INTEGER NOT NULL,
        doctor_name TEXT NOT NULL,
        specialization TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        experience INTEGER,
        license_number TEXT UNIQUE,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        address TEXT,
        public_key TEXT,
        private_key TEXT,
        profile_pic TEXT,
        status TEXT DEFAULT 'Active',
        FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id)
    )
    """)

    # ================= REPORTS TABLE =================
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT,

        sender_id INTEGER,
        receiver_id INTEGER,

        patient_number TEXT UNIQUE,
        patient_name TEXT,
        age INTEGER,
        gender TEXT,

        diagnosis TEXT,
        prescription TEXT,

        report_file TEXT,
        xray_image TEXT,

        encrypted_file TEXT,
        encrypted_aes_key TEXT,
        stego_image TEXT,
        sha256_hash TEXT,
        

        status TEXT DEFAULT 'Uploaded',

        upload_date TEXT,
        sent_date TEXT,

        FOREIGN KEY(sender_id) REFERENCES doctors(doctor_id),
        FOREIGN KEY(receiver_id) REFERENCES doctors(doctor_id)
    )
    """)

    # ================= PASSWORD RESET TABLE =================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        reset_id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        otp TEXT,
        is_verified BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used BOOLEAN DEFAULT 0,
        expires_at TIMESTAMP,
        FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
    )
    """)

    # ================= DEFAULT ADMIN =================
    cursor.execute("""
    INSERT OR IGNORE INTO admins
    (username, password, name, email)
    VALUES (?, ?, ?, ?)
    """, (
        "admin",
        "admin123",
        "System Administrator",
        "admin@medisecure.com"
    ))

    conn.commit()
    conn.close()

    print("✅ Database and tables created successfully!")
    print("   - hospitals table created")
    print("   - admins table created")
    print("   - doctors table created (with profile_pic column)")
    print("   - reports table created")
    print("   - password_resets table created (with OTP columns)")
    print("   - Default admin created (admin/admin123)")


if __name__ == "__main__":
    create_database()