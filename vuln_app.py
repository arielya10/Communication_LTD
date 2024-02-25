# Standard library imports
import hashlib
import json
from datetime import datetime, timedelta

# Related third-party imports
from flask import Flask, render_template, url_for, redirect, request, flash, session, jsonify
from flask_mail import Mail, Message
from sqlalchemy.sql import text

# Local application/library specific imports
from functions import *
from models import db, User, Customer

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  

# Configuration for SQLAlchemy (using SQLite for simplicity)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db.init_app(app)

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)
    for key, value in config.items():
        app.config[key] = value
    mail = Mail(app)  # Initialize Flask-Mail with app configuration

#vulnerable login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get username and password from form
        username = request.form.get('username')
        password = request.form.get('password')
        query = f"SELECT * FROM user WHERE username = '{username}'"
        with db.engine.connect() as conn:
            result = conn.execute(text(query))
            user = result.fetchone()
        if user:
            # Hash the provided password using the salt stored for this user
            provided_password_hash, _ = hash_password_hmac(password, bytes.fromhex(user.salt))
            sql = f"SELECT * FROM user WHERE username = '{username}' AND password = '{provided_password_hash.hex()}'"
            # Execute raw SQL query using text()
            with db.engine.connect() as conn:
                result = conn.execute(text(sql))
                user = result.fetchone()
        if user:
            # Logic after successful login
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            # Flash message for unsuccessful login
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')

# Vulnerable user registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get username, email, and password from form
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password, salt = hash_password_hmac(password)

        # Directly using user input in SQL queries makes the application vulnerable to SQL Injection
        query = f"INSERT INTO user (username, email, password, salt) VALUES ('{username}', '{email}', '{hashed_password.hex()}', '{salt.hex()}')"

        try:
            with db.engine.connect() as conn:
                conn.execute(text(query))
                db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('register.html')

# Home page route (after successful login)
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
            # Change Password functionality
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            user_id = session.get('user_id')
            user = User.query.filter_by(id=user_id).first()

            if user:
                provided_current_password_hash, _ = hash_password_hmac(current_password, bytes.fromhex(user.salt))
                if provided_current_password_hash.hex() == user.password:
                    is_valid, message = complexity_checks(user, new_password, config, True)
                    if not is_valid:
                        flash(message, 'danger')
                    else:
                        # Update the user's password here
                        flash('Password changed successfully', 'success')
                else:
                    flash('Current password is incorrect', 'danger')


    return render_template('home.html')

# Password recovery route
@app.route('/password-recovery', methods=['GET', 'POST'])
def password_recovery():
    stage = request.args.get('stage', 'request')
    email = request.args.get('email', None)

    if request.method == 'POST':
        email = request.form.get('email', email)

        if stage == 'request':
            # Logic for requesting password reset
            user = User.query.filter_by(email=email).first()
            if user:
                # Generate a random value and SHA-1 hash it
                random_value = os.urandom(16)
                hash_object = hashlib.sha1(random_value)
                password_reset_token = hash_object.hexdigest()
                user.reset_token = password_reset_token
                user.reset_token_created_at = datetime.utcnow()
                db.session.commit()

                msg = Message('Password Reset Request', sender=config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your password reset token is: {password_reset_token}'
                mail.send(msg)
                flash('An email with the password reset token has been sent.', 'info')
                return redirect(url_for('password_recovery', stage='verify', email=email))
            else:
                flash('No account associated with this email.', 'danger')

        
        elif stage == 'verify':
            # Logic for verifying token
            token = request.form.get('token')
            user = User.query.filter_by(email=email).first()

            if user and user.reset_token == token:
                token_age = datetime.utcnow() - user.reset_token_created_at
                if token_age <= timedelta(minutes=5):
                    return redirect(url_for('password_recovery', stage='reset', email=email))
                else:
                    flash('Token has expired.', 'danger')
            else:
                flash('Invalid token.', 'danger')

        elif stage == 'reset':
            # Logic for resetting the password
            new_password = request.form.get('new_password')
            user = User.query.filter_by(email=email).first()

            if user:
                is_valid, message = complexity_checks(user, new_password, config, True)
                if not is_valid:
                    flash(message, 'danger')
                    return render_template('password_recovery.html', stage=stage, email=email)

                hashed_password, _ = hash_password_hmac(new_password, bytes.fromhex(user.salt))
                user.password = hashed_password
                user.must_reset_password = False
                user.login_attempts = 0
                db.session.commit()

                flash('Your password has been reset successfully.', 'success')
                return redirect(url_for('login'))


    return render_template('password_recovery.html', stage=stage, email=email)

# Add customer route from home page
@app.route('/add_customer', methods=['POST'])
def add_customer():
    if request.method == 'POST':
        # Directly getting data from the form without sanitization
        id = request.form.get('id')
        name = request.form.get('name')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        user_id = session.get('user_id')  

        # Assuming all fields are filled for simplicity
        # WARNING: The following line is intentionally vulnerable to Stored XSS
        # Do not sanitize or validate inputs for HTML/JS content
        new_customer = Customer(id=id, name=name, lastname=lastname, email=email, user_id=user_id)
        
        db.session.add(new_customer)
        db.session.commit()

        return jsonify({'status': 'success', 'message': f'{name} {lastname} has been added successfully.'})

if __name__ == '__main__':
    app.run(debug=True)