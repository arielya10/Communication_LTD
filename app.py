from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json
import re
import hashlib
import os
from flask_mail import Mail, Message


# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key


# Configuration for SQLAlchemy (using SQLite for simplicity)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)  # Initialize SQLAlchemy with app configuration

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)
    for key, value in config.items():
        app.config[key] = value
    mail = Mail(app)  # Initialize Flask-Mail with app configuration


# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    previous_password_1 = db.Column(db.String(60), nullable=True)
    previous_password_2 = db.Column(db.String(60), nullable=True)
    previous_password_3 = db.Column(db.String(60), nullable=True)  
    login_attempts = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

def complexity_checks(user, new_password, update=False):
    # Initial password length and pattern checks
    if len(new_password) < config['password_length']:
        return False, f'Password must be at least {config["password_length"]} characters long.'

    complexity = config['password_complexity']
    if complexity['uppercase'] and not re.search(r'[A-Z]', new_password):
        return False, 'Password must contain an uppercase letter.'
    if complexity['lowercase'] and not re.search(r'[a-z]', new_password):
        return False, 'Password must contain a lowercase letter.'
    if complexity['numbers'] and not re.search(r'[0-9]', new_password):
        return False, 'Password must contain a number.'
    if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return False, 'Password must contain a special character.'

    # Dictionary check
    try:
        with open(config['dictionary_file'], 'r') as file:
            dictionary = file.read().splitlines()
        if new_password in dictionary:
            return False, 'Password is too common. Please choose a different one.'
    except FileNotFoundError:
        print(f"Dictionary file not found: {config['dictionary_file']}")

    # Check if the new password is valid (not used before)
    new_password_hash = generate_password_hash(new_password)
    if any(check_password_hash(old_password, new_password) for old_password in [user.password, user.previous_password_1, user.previous_password_2, user.previous_password_3] if old_password):
        return False, 'Password has been used before. Please choose a different one.'

    # Update password if requested
    if update:
        # Shift the old passwords
        user.previous_password_3 = user.previous_password_2
        user.previous_password_2 = user.previous_password_1
        user.previous_password_1 = user.password
        # Set the new password
        user.password = new_password_hash
        db.session.commit()

    return True, ''


# Login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        
        # Get username and password from form
        username = request.form.get('username')
        password = request.form.get('password')
    
        # Non-Vulnerable SQL Query
        user = User.query.filter_by(username=username).first()
        
        if user:
            
            # Check for failed login attempts
            if user.login_attempts >= config['login_attempts']:
                flash('Account locked due to too many failed login attempts.', 'danger')
                return render_template('login.html')
            
            # Validate user's password
            elif check_password_hash(user.password, password):
                user.login_attempts = 0  # Reset login attempts after successful login
                db.session.commit()
                return redirect(url_for('home'))
            
            # Increment login attempts after failed login
            else:
                user.login_attempts += 1
                db.session.commit()
                
        # Flash message for unsuccessful login
        flash('Login Unsuccessful. Please check username and password', 'danger')
        
    # Render login template
    return render_template('login.html')


# Home page route (after successful login)
@app.route('/home')
def home():
    return render_template('home.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        
        # Get username, email, and password from form   
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validation for email and username
        if not email or not username:
            flash('Email and Username are required!', 'danger')
            return render_template('register.html')

        # Check if username or email already exists in database
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return render_template('register.html')
        if existing_email:
            flash('An account with this email already exists.', 'danger')
            return render_template('register.html')
        
        # Create a new user instance for complexity check
        new_user = User(username=username, email=email, password=password)

        # Validate password complexity
        is_valid, message = complexity_checks(new_user, password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html',username=username, email=email)
        
        # Hash the password and create the user
        hashed_password = generate_password_hash(password)
        new_user.password = hashed_password  # Set hashed password
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a random value and SHA-1 hash it
            random_value = os.urandom(16)
            hash_object = hashlib.sha1(random_value)
            password_reset_token = hash_object.hexdigest()

            # Placeholder for sending email - implement with your email sending logic
            msg = Message('Password Reset Request', sender=config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your password reset token is: {password_reset_token}'
            mail.send(msg)
            flash('An email with the password reset token has been sent.', 'info')
            return redirect(url_for('verify_token', email=email))  # Redirect to token verification
        else:
            flash('No account associated with this email.', 'danger')
            return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/verify-token', methods=['GET', 'POST'])
def verify_token():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Invalid request.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')

        # Here you should verify the token. 
        # This is a placeholder logic. Replace it with your actual token verification logic.
        if token == user.reset_token:
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid token.', 'danger')

    return render_template('verify_token.html', email=email)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Invalid request.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = user.username
        new_password = request.form.get('new_password')

        # Validate password complexity
        is_valid, message = complexity_checks(user, new_password, True)
        if not is_valid:
            flash(message, 'danger')
            return render_template('reset_password.html', email=email)

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)


if __name__ == '__main__':
    app.run(debug=True)
