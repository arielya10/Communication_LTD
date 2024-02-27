# Standard library imports
import hashlib
import json
from datetime import datetime, timedelta
import sqlite3

# Related third-party imports
from flask import Flask, render_template, url_for, redirect, request, flash, session, jsonify
from flask_mail import Mail, Message

# Local application/library specific imports
from functions import *
from models import *

# Initialize the Flask application
app = Flask(__name__)

# Load configuration from a JSON file
with open('config.json') as config_file:
    config = json.load(config_file)
    # Apply configuration to the Flask app
    for key, value in config.items():
        app.config[key] = value
    # Initialize Flask-Mail with the app's configuration
    mail = Mail(app)

# Set a secret key for the application to use for session management
app.secret_key = config['secret_key']

# Define the database location
DATABASE = 'instance/site.db'

# Define a function to get a database connection
def get_db_connection():
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    # Use the sqlite3.Row factory for returning rows
    conn.row_factory = sqlite3.Row
    return conn

# Login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve username and password from form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate presence of username and password
        if not username or not password:
            flash('Both username and password are required', 'danger')
            return render_template('login.html')

        # Establish database connection
        conn = get_db_connection()
        # Fetch user record by username
        user = conn.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        # Check if user exists
        if user:
            # Check if the user's account is locked
            if user['login_attempts'] >= config['login_attempts']:
                conn.execute('UPDATE user SET must_reset_password = ? WHERE username = ?', (True, username))
                conn.commit()
                conn.close()
                flash('Your account has been locked. Please reset your password.', 'danger')
                return redirect(url_for('password_recovery'))

            # Hash the input password using the user's stored salt
            provided_password_hash, _ = hash_password_hmac(password, bytes.fromhex(user['salt']))

            # Compare the hashed password with the stored password
            if provided_password_hash.hex() == user['password']:
                # Reset login attempts
                conn.execute('UPDATE user SET login_attempts = 0 WHERE username = ?', (username,))
                # Reset the must_reset_password flag
                conn.execute('UPDATE user SET must_reset_password = ? WHERE username = ?', (False, username))
                conn.commit()
                # Store user's id in the session
                session['user_id'] = user['id']
                conn.close()
                # Redirect to the home page
                return redirect(url_for('home'))
            else:
                # Increce the login attempts
                conn.execute('UPDATE user SET login_attempts = login_attempts + 1 WHERE username = ?', (username,))
                conn.commit()
        conn.close()
        flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')

# Home page route (after successful login)
@app.route('/home', methods=['GET', 'POST'])
def home():
    # Check if the user is logged in
    if session.get('user_id') is None:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Change password route from the home page
        # Retrieve the current password and the new password from the form data
        current_password_input = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        user_id = session.get('user_id')
        conn = get_db_connection()
        
        # Fetch user record by user_id
        user = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
        # Check if user exists
        if not user:
            flash('User not found.', 'danger')
            conn.close()
            return render_template('home.html')
        
        # Hash the input current password using the user's stored salt
        current_password_hashed, _ = hash_password_hmac(current_password_input, bytes.fromhex(user['salt']))
        # Compare the hashed password with the stored password
        if current_password_hashed.hex() != user['password']:
            flash('Incorrect current password.', 'danger')
            return render_template('home.html')

        # Validate the new password
        is_valid, message = complexity_checks(new_password, config)
        if not is_valid:
            flash(message, 'danger')
        else:
            # Hash the new password using the user's stored salt
            new_password_hashed, _ = hash_password_hmac(new_password, bytes.fromhex(user['salt']))
            # Shift the previous passwords and update the user's password
            success, message = shift_previous_passwords(user_id, new_password_hashed.hex())
            if not success:
                flash(message, 'danger')  
            else:                
                # Update the user's password
                session['password'] = new_password_hashed.hex()
                # Reset login attempts
                session["login_attempts"] = 0
                # Reset the must_reset_password flag
                session["must_reset_password"] = False
                flash('Your password has been changed successfully.', 'success')
                return redirect(url_for('home'))

        conn.close()

    return render_template('home.html')

# Add customer route from home page
@app.route('/add_customer', methods=['POST'])
def add_customer():
    if request.method == 'POST':
        # Retrieve name, lastname, and email from the form data
        name = request.form.get('name')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        user_id = session.get('user_id')

        # Check if all fields are filled 
        if not (name and lastname and email):
            return jsonify({'status': 'error', 'message': 'All fields are required.'}), 400
        
        # Validate customer input
        is_valid, error_message = validate_input(name, lastname, email)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error_message}), 400

        conn = get_db_connection()
        # Check if the customer already exists in the database
        existing_customer = conn.execute('SELECT * FROM customer WHERE email = ?', (email,)).fetchone()
        if existing_customer:
            conn.close()
            return jsonify({'status': 'error', 'message': f'Customer with email {email} already exists.'}), 400

        # Add the customer to the database
        conn.execute('INSERT INTO customer (name, lastname, email, user_id) VALUES (?, ?, ?, ?)', 
                     (name, lastname, email, user_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': f'{name} {lastname} has been added successfully.'})

# Search customer route from the home page
@app.route('/search_customer', methods=['POST'])
def search_customer():
    if request.method == 'POST':
        # Retrieve name or lastname from the form
        user_id = session.get('user_id')
        
        search_query = request.form.get('search_customer', '').strip().lower()
        conn = get_db_connection()
        
        # Search for the customer in the database
        customers = conn.execute('SELECT * FROM customer WHERE user_id = ? AND (LOWER(name) = ? OR LOWER(lastname) = ?)', 
                                 (user_id, search_query, search_query)).fetchall()
        # Convert the customer records to a list of dictionaries
        customer_dicts = [{'name': c['name'], 'lastname': c['lastname'], 'email': c['email']} for c in customers]
        conn.close()
        return jsonify(customer_dicts)

# Logout route from the homepage
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve username, email, and password from the form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate presence of username, email, and password
        if not email or not username:
            flash('Email and Username are required!', 'danger')
            return render_template('register.html')
        
        # Validate email format
        if not validate_email(email):
            flash('Invalid email format.', 'danger')
            return render_template('register.html')

        # Validate username format
        if not username.isalnum():
            flash('Username can only contain letters and numbers.', 'danger')
            return render_template('register.html')
        
        conn = get_db_connection()
        
        # Check if the username or email already exists in the database
        existing_user = conn.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()
        existing_email = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()

        # If the username or email already exists, display an error message
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            conn.close()
            return render_template('register.html')
        if existing_email:
            flash('An account with this email already exists.', 'danger')
            conn.close()
            return render_template('register.html')

        # Validate the password
        is_valid, message = complexity_checks(password, config)
        if not is_valid:
            flash(message, 'danger')
            conn.close()
            return render_template('register.html', username=username, email=email)
        
        # Hash the password using HMAC and salt
        hashed_password, salt = hash_password_hmac(password)
        # Add the user to the database
        conn.execute('INSERT INTO user (username, email, password, salt) VALUES (?, ?, ?, ?)',
                     (username, email, hashed_password.hex(), salt.hex()))
        conn.commit()
        conn.close()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Password recovery route
@app.route('/password-recovery', methods=['GET', 'POST'])
def password_recovery():
    # Retrieve the stage and email from the query parameters
    stage = request.args.get('stage', 'request')
    email = request.args.get('email', None)

    if request.method == 'POST':
        # Retrieve the email from the form data
        email = request.form.get('email', email)

        conn = get_db_connection()

        # If the stage is 'request', send the password reset token to the user's email
        if stage == 'request':
            # Fetch the user record by email
            user = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()
            
            # If the user exists, generate a password reset token and send it to the user's email
            if user:
                random_value = os.urandom(16)
                hash_object = hashlib.sha1(random_value)
                password_reset_token = hash_object.hexdigest()
                
                # Update the user's record with the reset token and the token creation time
                conn.execute('UPDATE user SET reset_token = ?, reset_token_created_at = ? WHERE email = ?', 
                             (password_reset_token, datetime.utcnow(), email))
                conn.commit()

                # Send the password reset token to the user's email
                msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your password reset token is: {password_reset_token}'
                mail.send(msg)
                flash('An email with the password reset token has been sent.', 'info')
                return redirect(url_for('password_recovery', stage='verify', email=email))

            else:
                flash('No account associated with this email.', 'danger')

        # If the stage is 'verify', validate the token and redirect to the reset stage
        elif stage == 'verify':
            # Retrieve the token from the form data
            token = request.form.get('token')
            
            # Fetch the user record by email and token
            user = conn.execute('SELECT * FROM user WHERE email = ? AND reset_token = ?', (email, token)).fetchone()

            # If the token is valid, redirect to the reset stage
            if user:
                # Check if the token has expired
                token_age = datetime.utcnow() - datetime.strptime(user['reset_token_created_at'], '%Y-%m-%d %H:%M:%S.%f')
                if token_age <= timedelta(minutes=5):
                    return redirect(url_for('password_recovery', stage='reset', email=email))
                else:
                    flash('Token has expired.', 'danger')
            else:
                flash('Invalid token.', 'danger')

        # If the stage is 'reset', update the user's password and redirect to the login page
        elif stage == 'reset':
            # Retrieve the new password from the form data
            new_password = request.form.get('new_password')
            
            # Fetch the user record by email
            user = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()
            
            # If the user exists, validate the new password and update the user's password
            if user:
                # Validate the new password
                is_valid, message = complexity_checks(new_password, config)
                if not is_valid:
                    flash(message, 'danger')
                else:
                    # Hash the new password using the user's stored salt
                    new_password_hashed, _ = hash_password_hmac(new_password, bytes.fromhex(user['salt']))
                    # Shift the previous passwords and update the user's password
                    success, message = shift_previous_passwords(user['id'], new_password_hashed.hex())
                    if not success:
                        flash(message, 'danger')  
                    else:                
                        session['password'] = new_password_hashed.hex()
                        flash('Your password has been changed successfully.', 'success')
                        return redirect(url_for('login'))

            conn.close()
            
    return render_template('password_recovery.html', stage=stage, email=email)



if __name__ == '__main__':
    app.run(debug=True)
