# routes/student.py
from flask import Blueprint, render_template, redirect, url_for

# blueprint kept with url_prefix '/student'
student_bp = Blueprint('student', __name__,)

# redirect /student/ -> /student/dashboard
@student_bp.route('/')
def index():
    return redirect(url_for('student.dashboard'))

# dashboard route -> templates/student/dashboard.html
@student_bp.route('/dashboard')
def student_dashboard():
    return render_template('student/dashboard.html')

@student_bp.route('/firstyear')
def firstyear():
    # render a template like templates/student/firstyear.html or templates/firstyear.html
    return render_template('firstyear.html')

@student_bp.route('/secondyear')
def secondyear():
    return render_template('secondyear.html')

@student_bp.route('/thirdyear')
def thirdyear():
    return render_template('thirdyear.html')
