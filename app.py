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

app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'communication.Itd11@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'cyberproject'           # Your email password
mail = Mail(app)


# Configuration for SQLAlchemy (Temporary SQLite URI, can be changed later)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

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
    
def is_password_in_dictionary(password, dictionary_file):
    with open(dictionary_file, 'r') as file:
        dictionary = file.read().splitlines()
    return password in dictionary

def update_password(user, new_password):
    # Shift the old passwords
    user.previous_password_3 = user.previous_password_2
    user.previous_password_2 = user.previous_password_1
    user.previous_password_1 = user.password
    # Set the new password
    user.password = generate_password_hash(new_password)
    db.session.commit()

def is_new_password_valid(user, new_password):
    new_password_hash = generate_password_hash(new_password)
    return not any(check_password_hash(old_password, new_password) for old_password in [user.password, user.previous_password_1, user.previous_password_2, user.previous_password_3] if old_password)

# Login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if user.login_attempts >= config['login_attempts']:
                flash('Account locked due to too many failed login attempts.', 'danger')
                return render_template('login.html')
            elif check_password_hash(user.password, password):
                user.login_attempts = 0  # Reset login attempts after successful login
                db.session.commit()
                return redirect(url_for('home'))
            else:
                user.login_attempts += 1  # Increment login attempts
                db.session.commit()
        flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')


# Home page route (after successful login)
@app.route('/home')
def home():
    return render_template('home.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate email and username
        if not email or not username:
            flash('Email and Username are required!', 'danger')
            return render_template('register.html')

        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return render_template('register.html')
        if existing_email:
            flash('An account with this email already exists.', 'danger')
            return render_template('register.html')

        # Validate password
        if len(password) < config['password_length']:
            flash(f'Password must be at least {config["password_length"]} characters long.', 'danger')
            return render_template('register.html')

        # Complexity checks
        complexity = config['password_complexity']
        if complexity['uppercase'] and not re.search(r'[A-Z]', password):
            flash('Password must contain an uppercase letter.', 'danger')
            return render_template('register.html')
        if complexity['lowercase'] and not re.search(r'[a-z]', password):
            flash('Password must contain a lowercase letter.', 'danger')
            return render_template('register.html')
        if complexity['numbers'] and not re.search(r'[0-9]', password):
            flash('Password must contain a number.', 'danger')
            return render_template('register.html')
        if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password must contain a special character.', 'danger')
            return render_template('register.html')

        # Dictionary check
        if is_password_in_dictionary(password, config['dictionary_file']):
            flash('Password is too common. Please choose a different one.', 'danger')
            return render_template('register.html')

        # Hash the password and create the user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

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
            msg = Message('Password Reset Request', sender='your-email@example.com', recipients=[email])
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
        new_password = request.form.get('new_password')
        # Perform the same password validations as in registration
        if len(new_password) < config['password_length']:
            flash(f'Password must be at least {config["password_length"]} characters long.', 'danger')
        elif not all([complexity_checks(new_password)]):
            flash('Password does not meet complexity requirements.', 'danger')
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)




if __name__ == '__main__':
    app.run(debug=True)
