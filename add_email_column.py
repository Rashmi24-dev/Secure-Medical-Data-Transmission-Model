import sqlite3

def add_email_column():
    conn = sqlite3.connect('medical.db')
    cursor = conn.cursor()
    
    # Check if email column exists in admins table
    cursor.execute("PRAGMA table_info(admins)")
    columns = cursor.fetchall()
    
    email_exists = False
    for col in columns:
        if col[1] == 'email':
            email_exists = True
            break
    
    if not email_exists:
        print("Adding email column to admins table...")
        cursor.execute("ALTER TABLE admins ADD COLUMN email TEXT")
        conn.commit()
        print("Email column added successfully!")
    else:
        print("Email column already exists.")
    
    # Update admin with email (replace 'admin' with your username and 'your-email@gmail.com' with your email)
    admin_username = 'admin'  # Change this to your admin username
    admin_email = 'your-email@gmail.com'  # Change this to your email
    
    cursor.execute("SELECT * FROM admins WHERE username = ?", (admin_username,))
    admin = cursor.fetchone()
    
    if admin:
        cursor.execute("UPDATE admins SET email = ? WHERE username = ?", (admin_email, admin_username))
        conn.commit()
        print(f"Updated admin '{admin_username}' with email: {admin_email}")
    else:
        print(f"Admin with username '{admin_username}' not found!")
        print("Please create an admin account first.")
    
    # Show all admins
    cursor.execute("SELECT admin_id, username, email FROM admins")
    admins = cursor.fetchall()
    print("\nCurrent Admins:")
    for admin in admins:
        print(f"  ID: {admin[0]}, Username: {admin[1]}, Email: {admin[2]}")
    
    conn.close()

if __name__ == "__main__":
    add_email_column()