from flask import render_template, redirect, url_for, flash, request
from app import app, db, models
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)

        # Assign 'admin' role to the first user, 'pilot' to others
        if User.query.count() == 0:
            new_user.role = User.ROLE_ADMIN
        else:
            new_user.role = User.ROLE_PILOT

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == User.ROLE_ADMIN:
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    elif current_user.role == User.ROLE_PILOT:
        return render_template('pilot_dashboard.html', username=current_user.username)
    else:
        # Fallback or error, though ideally all users have a valid role
        flash('User role not recognized.', 'error')
        return redirect(url_for('index'))

@app.route('/admin/assign-role/<username>/<role>')
@login_required
def assign_role(username, role):
    if not current_user.role == User.ROLE_ADMIN:
        flash('Unauthorized: Only admins can assign roles.', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f'User {username} not found.', 'error')
        return redirect(url_for('dashboard'))

    if role not in [User.ROLE_ADMIN, User.ROLE_PILOT]:
        flash(f'Invalid role: {role}.', 'error')
        return redirect(url_for('dashboard'))

    user.role = role
    db.session.commit()
    flash(f'Role for user {username} updated to {role}.', 'success')
    return redirect(url_for('dashboard'))
