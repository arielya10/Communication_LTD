# Standard library imports
import hashlib
import json
from datetime import datetime, timedelta

# Related third-party imports
from flask import Flask, render_template, url_for, redirect, request, flash, session, jsonify
from flask_mail import Mail, Message
from sqlalchemy import func

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
            if user.login_attempts >= 3:
                user.must_reset_password = True
                flash('Your account has been locked. Please reset your password.', 'danger')
                return redirect(url_for('password_recovery'))
            # Hash the provided password using the salt stored for this user
            provided_password_hash, _ = hash_password_hmac(password, bytes.fromhex(user.salt))

            # Check if hashed password matches the one in the database
            if provided_password_hash.hex() == user.password:
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
        is_valid, message = complexity_checks(new_user, password, config, True)
        if not is_valid:    
            flash(message, 'danger')
            return render_template('register.html',username=username, email=email)
        
        # Hash the password with HMAC and a new salt
        hashed_password, salt = hash_password_hmac(password)
        new_user = User(username=username, email=email, password=hashed_password.hex(), salt=salt.hex())
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
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
                is_valid, message = complexity_checks(user, new_password, config, True)
                if not is_valid:
                    flash(message, 'danger')
                    return render_template('password_recovery.html', stage=stage, email=email)

                hashed_password, _ = hash_password_hmac(new_password, bytes.fromhex(user.salt))
                user.password = hashed_password.hex()
                user.must_reset_password = False
                user.login_attempts = 0
                db.session.commit()

                flash('Your password has been reset successfully.', 'success')
                return redirect(url_for('login'))


    return render_template('password_recovery.html', stage=stage, email=email)


if __name__ == '__main__':
    app.run(debug=True)
