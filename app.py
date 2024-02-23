from flask import Flask, render_template, url_for, redirect, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy import func
import hashlib
import hmac
import json
import re
import hashlib
import os
from flask_mail import Mail, Message
from datetime import datetime, timedelta



# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  


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
    must_reset_password = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_created_at = db.Column(db.DateTime, nullable=True)
    salt = db.Column(db.String(16), nullable=False)
    customers = db.relationship('Customer', backref='creator', lazy=True)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    


    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    
# hash password using HMAC and salt
def hash_password_hmac(password, salt=None):
    if salt is None:
        # Generate a new salt
        salt = os.urandom(16)
    # Ensure that salt is bytes
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    # Create HMAC hash of the password
    password_hash = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).digest()
    return password_hash, salt

# Password complexity checks
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

    try:
        with open(config['dictionary_file'], 'r', encoding='utf-8', errors='ignore') as file:
            dictionary = file.read().splitlines()
        if new_password in dictionary:
            return False, 'Password is too common. Please choose a different one.'
    except FileNotFoundError:
        print(f"Dictionary file not found: {config['dictionary_file']}")

    # Check if the new password is valid (not used before)
    new_password_hash, _ = hash_password_hmac(new_password, user.salt)
    if new_password_hash == user.password or new_password_hash == user.previous_password_1 or new_password_hash == user.previous_password_2 or new_password_hash == user.previous_password_3:
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

def validate_email(email):
    # Email format validation
    email_regex_pattern = r'^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex_pattern, email))


# Validate input
def validate_input(id,name,lastname,email):
    # ID validation
    if not id.isdigit():
        return False, 'Invalid ID format.'

    # name validation 
    if not name.isalpha():
        return False, 'Invalid name format.'

    # last name validation 
    if not lastname.isalpha():
        return False, 'Invalid last name format.'

    # email validation
    if not validate_email(email):
        return False, 'Invalid email format.'

    
    return True, ''

# Login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get username and password from form
        username = request.form.get('username')
        password = request.form.get('password')

        # Query the user by username
        user = User.query.filter_by(username=username).first()

        if user:
            # Hash the provided password using the salt stored for this user
            provided_password_hash, _ = hash_password_hmac(password, user.salt)

            # Check if hashed password matches the one in the database
            if provided_password_hash == user.password:
                # Reset login attempts and update session information
                user.login_attempts = 0
                db.session.commit()
                session['user_id'] = user.id

                # Redirect to home page or dashboard after successful login
                return redirect(url_for('home'))

            else:
                # Increment login attempts after a failed login
                user.login_attempts += 1
                db.session.commit()

        # Flash message for unsuccessful login
        flash('Login Unsuccessful. Please check username and password', 'danger')

    # Render login template
    return render_template('login.html')

#vulnerable login page route (main page)
@app.route('/vulnerable_login', methods=['GET', 'POST'])
def vulnerable_login():
    if request.method == 'POST':
        # Get username and password from form
        username = request.form.get('username')
        password = request.form.get('password')

        sql = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"

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
                provided_current_password_hash, _ = hash_password_hmac(current_password, user.salt)
                if provided_current_password_hash == user.password:
                    is_valid, message = complexity_checks(user, new_password, True)
                    if not is_valid:
                        flash(message, 'danger')
                    else:
                        # Update the user's password here
                        flash('Password changed successfully', 'success')
                else:
                    flash('Current password is incorrect', 'danger')


    return render_template('home.html')

# Add customer route from home page
@app.route('/add_customer', methods=['POST'])
def add_customer():
    if request.method == 'POST':
        id = request.form.get('id')
        name = request.form.get('name')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        user_id = session.get('user_id')  

        # Check if all fields are filled 
        if not (id and name and lastname and email):
            return jsonify({'status': 'error', 'message': 'All fields are required.'}), 400
        
        # Validate customer input
        is_valid, error_message = validate_input(id, name, lastname, email)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error_message}), 400
        
        # Check if the customer already exist in the database
        existing_customer = Customer.query.filter_by(id=id).first()
        if existing_customer:
            return jsonify({'status': 'error', 'message': f'Customer with ID {id} already exists.'}), 400
        
        # Create New Customer instance
        new_customer = Customer(id=id, name=name, lastname=lastname, email=email, user_id=user_id)
        db.session.add(new_customer)
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'{name} {lastname} has been added successfully.'})

# Search customer route from the home page
@app.route('/search_customer', methods=['GET', 'POST'])
def search_customer():
    if request.method == 'POST':
        user_id = session.get('user_id') 
        # Handle white spcaes and lower case sensitivity
        search_query = request.form.get('search_customer', '').strip().lower()
        # Query to find customers that match the logged-in user
        customers = Customer.query.filter(
            Customer.user_id == user_id,
            db.or_(
                func.lower(Customer.name) == search_query,
                func.lower(Customer.lastname) == search_query,
                Customer.id == search_query,
                  )
                    ).all()
        # list of dictionaries from the query results
        customer_dicts = [{'id': c.id, 'name': c.name, 'lastname': c.lastname, 'email': c.email} for c in customers]
        # return the search results as a json
        return jsonify(customer_dicts)

# Logout route from the homepage
@app.route('/logout')
def logout():
    # Clear data from session
    session.clear()
    flash('You have been logged out successfully.', 'info')
    # Redirect back to login page
    return redirect(url_for('login'))



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
        
        if not validate_email(email):
            flash('Invalid email format.', 'danger')
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
        
        # Hash the password with HMAC and a new salt
        hashed_password, salt = hash_password_hmac(password)
        new_user = User(username=username, email=email, password=hashed_password, salt=salt)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Vulnerable user registration route
@app.route('/vulnerable_register', methods=['GET', 'POST'])
def vulnerable_register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        sql = "INSERT INTO user (username, email, password) VALUES ('{}', '{}', '{}')".format(username, email, password)

        try:
            with db.engine.begin() as conn:  
                conn.execute(text(sql))
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')

    return render_template('register.html')




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
                is_valid, message = complexity_checks(user, new_password, True)
                if not is_valid:
                    flash(message, 'danger')
                    return render_template('password_recovery.html', stage=stage, email=email)

                hashed_password, _ = hash_password_hmac(new_password, user.salt)
                user.password = hashed_password
                user.must_reset_password = False
                user.login_attempts = 0
                db.session.commit()

                flash('Your password has been reset successfully.', 'success')
                return redirect(url_for('login'))


    return render_template('password_recovery.html', stage=stage, email=email)


if __name__ == '__main__':
    app.run(debug=True)

