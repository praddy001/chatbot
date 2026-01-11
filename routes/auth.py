# routes/auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from itsdangerous import URLSafeTimedSerializer
from extensions import db, limiter
from models.user import User
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__, url_prefix='')

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.role != role:
                return render_template('login.html', error='Invalid credentials or wrong role selected.')
            session['user'] = user.username
            session['user_role'] = user.role
            session['user_name'] = user.name or user.username
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    if 'user' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower() if request.form.get("email") else None

        if not username or not password:
            return render_template("register.html", error="Username and password are required.")

        if User.query.filter((User.username==username) | (User.email==email)).first():
            return render_template("register.html", error="Username or email already taken.")

        user = User(username=username, email=email, role=role, name=name or username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash("Please enter your email.", "danger")
            return redirect(url_for('auth.forgot_password'))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return redirect(url_for('auth.forgot_password'))

        serializer = URLSafeTimedSerializer(current_app.secret_key)
        token = serializer.dumps(email, salt='reset-password')
        reset_link = url_for('auth.reset_password', token=token, _external=True)
        # TODO: send actual email; for now print link
        print("RESET LINK:", reset_link)
        flash("Password reset link has been sent (check server console during dev).", "success")
        return redirect(url_for('auth.login'))

    return render_template('forgot.html')

@auth_bp.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = URLSafeTimedSerializer(current_app.secret_key)
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except Exception:
        flash("Reset link expired or invalid.", "danger")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        new_pass = request.form.get('password')
        if not new_pass:
            flash("Enter a new password.", "danger")
            return redirect(url_for('auth.reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('auth.login'))

        user.set_password(new_pass)
        db.session.commit()
        flash("Password successfully reset!", "success")
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html')
