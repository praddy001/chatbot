from app import app, db, User

STAFF_USERNAME = "staff3"  # <-- change if needed
NEW_PASSWORD = "Admin123"  # <-- your new password

with app.app_context():
    user = User.query.filter_by(username=STAFF_USERNAME.lower()).first()
    if not user:
        print("❌ User not found:", STAFF_USERNAME)
    else:
        user.set_password(NEW_PASSWORD)
        db.session.commit()
        print("✅ Password reset successful for:", user.username)
        print("➡ New password:", NEW_PASSWORD)
