from flask_mail import Mail, Message
from app import app, mail

with app.app_context():
    try:
        msg = Message(
            subject="Test Email from MediSecure",
            recipients=["your-email@gmail.com"],  # Replace with your email
            body="This is a test email to verify mail configuration is working."
        )
        mail.send(msg)
        print("✅ Test email sent successfully!")
        print("Please check your inbox/spam folder.")
    except Exception as e:
        print(f"❌ Error sending test email: {e}")