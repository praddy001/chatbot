# app.py  — single-file Flask app with DB, CSRF, migrations, AI (optional), and debug-friendly chat API.
import os
import io
import logging
from functools import wraps
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from traceback import format_exc
from flask import request, flash, redirect, url_for
from werkzeug.utils import secure_filename

# -----------------------
# Load .env explicitly (force path)
# -----------------------
BASE_DIR = os.path.dirname(__file__)
dotenv_path = os.path.join(BASE_DIR, ".env")
# load explicitly and override any existing env vars (for determinism during dev)
_loaded = load_dotenv(dotenv_path=dotenv_path, override=True)

print("dotenv load_dotenv returned:", _loaded)
print("WORKING DIRECTORY:", os.getcwd())
print("Looking for .env at:", dotenv_path)
try:
    # print a few lines (debug only)
    with io.open(dotenv_path, "r", encoding="utf-8") as f:
        for i in range(5):
            line = f.readline()
            if not line:
                break
            print(f".env line {i+1:02d}:", line.rstrip("\n"))
except Exception as e:
    print("Could not read .env file (ok if missing):", e)

# -----------------------
# App and config
# -----------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
# Secret must exist for session and CSRF
app.secret_key = os.environ.get("FLASK_SECRET") or "dev-secret-change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URI", f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Logging
app.logger.setLevel(logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.DEBUG)

# -----------------------
# Extensions
# -----------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")

# -----------------------
# AI init (optional)
# -----------------------
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
print("GOOGLE_API_KEY from env (first 8 chars):", (GOOGLE_API_KEY[:8] + '...') if GOOGLE_API_KEY else None)

AI_ENABLED = False
ai_model = None

if GOOGLE_API_KEY:
    try:
        import google.generativeai as genai  # may raise ImportError
        genai.configure(api_key=GOOGLE_API_KEY)
        # use a model that exists in your SDK / plan; adapt if needed
        try:
            ai_model = genai.GenerativeModel("models/gemini-2.5-flash")
        except Exception:
            # fallback to default if above fails
            ai_model = genai.GenerativeModel()
        AI_ENABLED = True
        app.logger.info("AI model initialized.")
    except Exception as e:
        app.logger.warning("Could not initialize google.generativeai: %s", e)
        AI_ENABLED = False
else:
    app.logger.info("No GOOGLE_API_KEY; AI disabled.")

# expose flags in config for easy access
app.config['AI_ENABLED'] = AI_ENABLED
app.config['AI_MODEL'] = ai_model

# -----------------------
# Models
# -----------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")
    name = db.Column(db.String(120), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

# -----------------------
# Helpers / decorators
# -----------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            # for AJAX return JSON 401 so client can handle
            if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

def staff_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if session.get('user_role') != 'staff':
            flash('Access denied. Staff access required.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

# -----------------------
# Utilities
# -----------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXT = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def auto_register_routes(app, templates_dir="templates"):
    skip = {"login.html", "register.html", "index.html", "student_dashboard.html", "staff_dashboard.html"}
    if not os.path.isdir(templates_dir):
        return
    for root, dirs, files in os.walk(templates_dir):
        for f in files:
            if not f.endswith(".html"):
                continue
            if f in skip:
                continue
            rel_path = os.path.relpath(os.path.join(root, f), templates_dir).replace("\\", "/")
            rel_path_sanitized = rel_path.replace(" ", "_")
            route = "/" + rel_path_sanitized.replace(".html", "")
            endpoint = rel_path_sanitized.replace("/", "_").replace(".html", "").lower()
            if endpoint in app.view_functions:
                continue
            def view_func(template=rel_path):
                try:
                    return render_template(template)
                except Exception:
                    return f"<pre>Template render error for {template}:\n\n{format_exc()}</pre>", 500
            app.add_url_rule(route, endpoint, view_func)
            app.logger.debug("[AUTO] route: %s -> template %s", route, rel_path)

# -----------------------
# Routes: Home / generic pages
# -----------------------
@app.route("/")
def home():
    try:
        return render_template('index.html')
    except Exception:
        return f"<pre>Index render error:\n\n{format_exc()}</pre>", 500

@app.route("/page/<path:page>")
def generic_page(page):
    try:
        return render_template(page)
    except Exception:
        return "Page not found", 404

# -----------------------
# Auth routes
# -----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if 'user' in session:
            return redirect(url_for('home'))
        return render_template('login.html')
    # POST
    username_or_email = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username_or_email or not password:
        return render_template('login.html', error="Please enter username/email and password.")
    # try username first
    user = User.query.filter_by(username=username_or_email.lower()).first()
    if not user:
        user = User.query.filter_by(email=username_or_email.lower()).first()
    app.logger.debug("Login attempt for: %s -> found: %s", username_or_email, bool(user))
    if not user or not user.check_password(password):
        return render_template('login.html', error="Invalid username/email or password.")
    session['user'] = user.username
    session['user_role'] = user.role
    session['user_name'] = user.name or user.username
    next_page = request.args.get('next')
    return redirect(next_page or url_for('home'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower() or None

        if not username or not password:
            return render_template("register.html", error="Username and password are required.")

        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="Username already taken.")

        if email and User.query.filter_by(email=email).first():
            return render_template("register.html", error="Email already taken.")

        user = User(username=username, email=email, role=role, name=name or username)
        user.set_password(password)
        db.session.add(user)
        from sqlalchemy.exc import IntegrityError
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return render_template("register.html", error="Username or email already taken.")

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

# Forgot / reset password (simple flow; you must wire email sending if desired)
@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return redirect(url_for('forgot_password'))
        serializer = URLSafeTimedSerializer(app.secret_key)
        token = serializer.dumps(email, salt='reset-password')
        reset_link = url_for('reset_password', token=token, _external=True)
        print("RESET LINK (dev):", reset_link)
        flash("Password reset link printed to console (dev).", "success")
        return redirect(url_for('login'))
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except Exception:
        flash("Reset link expired or invalid.", "danger")
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_pass = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(new_pass)
            db.session.commit()
            flash("Password reset successful", "success")
            return redirect(url_for('login'))
        flash("User not found", "danger")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# -----------------------
# Dashboard
# -----------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_role = session.get('user_role')
    user_name = session.get('user_name')
    department = session.get('department', 'Department')  # Add department if available
    
    if user_role == 'staff':
        return render_template('staff/dashboard.html', 
                             staff_name=user_name,
                             department=department,
                             uploads=0,  # Add actual counts from database
                             events=0,
                             students=0)
    
    user_course = session.get('user_course', 'FY - Computer Science')  # Add course if available
    return render_template('student/dashboard.html', 
                         user_name=user_name,
                         user_course=user_course,
                         stats={},  # Add actual stats
                         notes=[],  # Add actual notes
                         events=[])  # Add actual events

# -----------------------
# Student routes (inline)
# -----------------------

@app.route("/student/")
def student_index():
    return render_template('dashboard.html')

@app.route("/student/firstyear")
def firstyear():
    return render_template('firstyear.html')

@app.route("/student/secondyear")
def secondyear():
    return render_template('secondyear.html')

@app.route("/student/thirdyear")
def thirdyear():
    return render_template('thirdyear.html')

# dynamic subject route -> templates/subjects/<year>/<subject>.html
@app.route("/student/<year>/<subject>")
def subject_page(year, subject):
    allowed_years = {'firstyear','secondyear','thirdyear'}
    if year not in allowed_years:
        abort(404)
    template_path = f"subjects/{year}/{subject}.html"
    try:
        return render_template(template_path, year=year, subject=subject)
    except Exception:
        return f"Template missing or render error: {template_path}", 404

@app.route("/staff/upload", methods=['POST'])
@login_required
def staff_upload():
    if session.get('user_role') != 'staff':
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        filename = secure_filename(file.filename)
        
        # Define your upload folder
        UPLOAD_FOLDER = 'uploads/notes'  # Change this to your preferred path
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        # Save the file
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        
        flash('File uploaded successfully!', 'success')
    
    return redirect(url_for('dashboard'))

# -----------------------
# API: ping (diagnostic)
# -----------------------
@app.route("/api/ping", methods=["POST"])
def api_ping():
    app.logger.info(">> /api/ping received session_user=%s", session.get('user'))
    return jsonify({"ok": True, "session_user": session.get('user'), "session_exists": 'user' in session})

# -----------------------
# API: chat (debug-friendly)
# -----------------------
@app.route("/api/chat", methods=["POST"])
@limiter.limit("20 per minute")
@login_required_api
def api_chat():
    app.logger.info(">> /api/chat hit by user=%s", session.get('user'))
    try:
        data = request.get_json(silent=True)
        app.logger.debug("Raw JSON payload: %r", data)
        if not data or not isinstance(data, dict):
            return jsonify({"error":"Invalid JSON payload"}), 400

        query = (data.get("query") or "").strip()
        history = data.get("history", [])
        if not query:
            return jsonify({"error":"Please send a question."}), 400

        # show AI state
        app.logger.info("AI_ENABLED=%s model_present=%s", app.config.get('AI_ENABLED'), bool(app.config.get('AI_MODEL')))
        if not app.config.get('AI_ENABLED') or app.config.get('AI_MODEL') is None:
            return jsonify({"answer":"⚠️ AI is not configured. Please check your GOOGLE_API_KEY in .env file."}), 500

        # Build simple conversation string
        system_prompt = "You are a helpful AI student assistant. Keep replies short and friendly."
        conversation = system_prompt + "\n\n"
        recent_history = history[-6:] if isinstance(history, list) else []
        for msg in recent_history:
            role = msg.get('role', 'user')
            content = msg.get('content','')
            conversation += f"{'User' if role=='user' else 'Assistant'}: {content}\n"
        conversation += f"User: {query}\nAssistant:"

        app.logger.debug("Calling model.generate_content() with conversation (trimmed): %s", conversation[:1000])
        try:
            response = app.config['AI_MODEL'].generate_content(conversation)
            app.logger.debug("Model response repr: %r", response)
            answer = getattr(response, 'text', None) or (response if isinstance(response, str) else None)
            if not answer:
                if isinstance(response, dict):
                    answer = response.get('text') or response.get('output') or str(response)
            if not answer:
                answer = "⚠️ AI returned empty response."
            app.logger.info("AI answered (len=%d)", len(answer))
            return jsonify({"answer": answer, "user": session.get('user')}), 200
        except Exception as e:
            app.logger.exception("AI call error")
            return jsonify({"answer": f"AI call error: {e}"}), 500

    except Exception as e:
        app.logger.exception("Unhandled /api/chat error")
        return jsonify({"error": f"Server error: {e}"}), 500

# -----------------------
# Context processor for templates
# -----------------------
@app.context_processor
def inject_user():
    return dict(current_user=session.get('user'), user_role=session.get('user_role'), user_name=session.get('user_name'))

# -----------------------
# Auto-register remaining template-based routes
# -----------------------
auto_register_routes(app)

# -----------------------
# Startup: create DB tables and print registered routes
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("\n=== Registered routes ===")
        for rule in app.url_map.iter_rules():
            print(f"{rule.endpoint:30} -> {rule.rule}")
        print("=========================\n")
    app.run(debug=True)


