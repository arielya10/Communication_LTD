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

#vulnerable login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve username and password from the form data
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate presence of username and password
        if not username or not password:
            flash('Both username and password are required', 'danger')
            return render_template('login.html')

        conn = get_db_connection()

        # Vulnerable SQL query to fetch the user record by username
        # For exmaple, if the username is "user'--" the query will return the first user record
        query = "SELECT * FROM user WHERE username = '{}'".format(username)
        user = conn.execute(query).fetchone()

        # Check if the user exists
        if user:
            # Check if the user's account is locked
            if user['login_attempts'] >= config['login_attempts']:
                conn.execute("UPDATE user SET must_reset_password = 1 WHERE username = '{}'".format(username))
                conn.commit()
                conn.close()
                flash('Your account has been locked. Please reset your password.', 'danger')
                return redirect(url_for('password_recovery'))

            # Hash the input password using the user's stored salt
            provided_password_hash, _ = hash_password_hmac(password, bytes.fromhex(user['salt']))
            # Compare the hashed password with the stored password
            query = "SELECT * FROM user WHERE username = '{}' AND password = '{}'".format(username, provided_password_hash.hex())
            user = conn.execute(query).fetchone()
            # If the password is correct, reset the login attempts and redirect to the home page
            if user:
                # Reset the login attempts
                conn.execute("UPDATE user SET login_attempts = 0 WHERE username = '{}'".format(username))
                conn.commit()
                # Store the user's id in the session
                session['user_id'] = user['id']
                conn.close()
                return redirect(url_for('home'))
            else:
                # Increment the login attempts
                conn.execute("UPDATE user SET login_attempts = login_attempts + 1 WHERE username = '{}'".format(username))
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

        conn = get_db_connection()
        
        # Vulnerable SQL query to check if the customer already exists based on the email
        # For exmaple, if the email is "email@gmail.com'; DROP TABLE customer; --" the query will delete the customer table
        existing_customer_query = f"SELECT * FROM customer WHERE email = '{email}'"
        # Fetch the customer record by email
        existing_customer = conn.execute(existing_customer_query).fetchone()
        # Check if the customer already exists
        if existing_customer:
            conn.close()
            return jsonify({'status': 'error', 'message': f'Customer with email {email} already exists.'}), 400

        # Insert the new customer record into the database
        insert_customer_query = "INSERT INTO customer (name, lastname, email, user_id) VALUES (?, ?, ?, ?)"
        conn.execute(insert_customer_query, (name, lastname, email, user_id))
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
    # Redirect back to login page
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

        conn = get_db_connection()
        

        # Vulnerable SQL query to check if the username or email already exists
        # For exmaple, if the username is "user'; DROP TABLE user; --" the query will delete the user table
        existing_user_query = f"SELECT * FROM user WHERE username = '{username}'"
        existing_email_query = f"SELECT * FROM user WHERE email = '{email}'"

        # Fetch the user record by username and email
        existing_user = conn.executescript(existing_user_query).fetchone()
        existing_email = conn.executescript(existing_email_query).fetchone()

        # Check if the username or email already exists
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            conn.close()
            return render_template('register.html')
        if existing_email:
            flash('An account with this email already exists.', 'danger')
            conn.close()
            return render_template('register.html')

        # validate password complexity
        is_valid, message = complexity_checks(password, config)
        if not is_valid:
            flash(message, 'danger')
            conn.close()
            return render_template('register.html', username=username, email=email)
        
        # Hash the password and store the salt
        hashed_password, salt = hash_password_hmac(password)
        
        # Insert the new user record into the database
        insert_user_query = f"INSERT INTO user (username, email, password, salt) VALUES ('{username}', '{email}', '{hashed_password.hex()}', '{salt.hex()}')"
        conn.execute(insert_user_query)
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
                    success, message = shift_previous_passwords(user['id'], new_password.hex())
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
