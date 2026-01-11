# routes/staff.py
from flask import Blueprint, render_template
staff_bp = Blueprint('staff', __name__, url_prefix='/staff')

@staff_bp.route('/')
def staff_index():
    return render_template('staff_dashboard.html')
