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


# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  

# Configuration for SQLite
DATABASE = 'instance/site.db'


# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)
    for key, value in config.items():
        app.config[key] = value
    mail = Mail(app)  # Initialize Flask-Mail with app configuration

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Login page route (main page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        if user:
            if user['login_attempts'] >= config['login_attempts']:
                conn.execute('UPDATE user SET must_reset_password = ? WHERE username = ?', (True, username))
                conn.commit()
                conn.close()
                flash('Your account has been locked. Please reset your password.', 'danger')
                return redirect(url_for('password_recovery'))

            provided_password_hash, _ = hash_password_hmac(password, user['salt'])

            if provided_password_hash.hex() == user['password']:
                conn.execute('UPDATE user SET login_attempts = 0 WHERE username = ?', (username,))
                conn.commit()
                session['user_id'] = user['id']
                conn.close()
                return redirect(url_for('home'))
            else:
                conn.execute('UPDATE user SET login_attempts = login_attempts + 1 WHERE username = ?', (username,))
                conn.commit()
        conn.close()
        flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')

# Home page route (after successful login)
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        current_password_input = request.form.get('current_password')
        new_password = request.form.get('new_password')
        user_id = session.get('user_id')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found.', 'danger')
            conn.close()
            return render_template('home.html')
        
        # Hash the input current password using the user's stored salt
        current_password_hashed, _ = hash_password_hmac(current_password_input, user['salt'])
        
        if current_password_hashed.hex() != user['password']:
            flash('Incorrect current password.', 'danger')
            return render_template('home.html')

        is_valid, message = complexity_checks(new_password, config)
        if not is_valid:
            flash(message, 'danger')
        else:
            new_password_hashed, _ = hash_password_hmac(new_password, user['salt'])
            success, message = shift_previous_passwords(user_id, new_password_hashed.hex())
            if not success:
                flash(message, 'danger')  
            else:                
                session['password'] = new_password_hashed.hex()
                flash('Your password has been changed successfully.', 'success')
                return redirect(url_for('home'))

        conn.close()

    return render_template('home.html')

# Add customer route from home page
@app.route('/add_customer', methods=['POST'])
def add_customer():
    if request.method == 'POST':
        name = request.form.get('name')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        user_id = session.get('user_id')

        conn = get_db_connection()
        # Check if the customer already exists in the database
        existing_customer = conn.execute('SELECT * FROM customer WHERE email = ?', (email,)).fetchone()
        if existing_customer:
            conn.close()
            return jsonify({'status': 'error', 'message': f'Customer with email {email} already exists.'}), 400

        conn.execute('INSERT INTO customer (name, lastname, email, user_id) VALUES (?, ?, ?, ?)', 
                     (name, lastname, email, user_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': f'{name} {lastname} has been added successfully.'})

# Search customer route from the home page
@app.route('/search_customer', methods=['POST'])
def search_customer():
    if request.method == 'POST':
        user_id = session.get('user_id')
        search_query = request.form.get('search_customer', '').strip().lower()

        conn = get_db_connection()
        customers = conn.execute('SELECT * FROM customer WHERE user_id = ? AND (LOWER(name) = ? OR LOWER(lastname) = ?)', 
                                 (user_id, search_query, search_query)).fetchall()
        customer_dicts = [{'id': c['id'], 'name': c['name'], 'lastname': c['lastname'], 'email': c['email']} for c in customers]
        conn.close()
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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not username:
            flash('Email and Username are required!', 'danger')
            return render_template('register.html')
        
        if not validate_email(email):
            flash('Invalid email format.', 'danger')
            return render_template('register.html')

        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()
        existing_email = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()

        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            conn.close()
            return render_template('register.html')
        if existing_email:
            flash('An account with this email already exists.', 'danger')
            conn.close()
            return render_template('register.html')

        # Assuming complexity_checks function returns True if password is complex enough
        is_valid, message = complexity_checks(password, config)
        if not is_valid:
            flash(message, 'danger')
            conn.close()
            return render_template('register.html', username=username, email=email)
        
        hashed_password, salt = hash_password_hmac(password)
        conn.execute('INSERT INTO user (username, email, password, salt) VALUES (?, ?, ?, ?)',
                     (username, email, hashed_password.hex(), salt))
        conn.commit()
        conn.close()
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

        conn = get_db_connection()

        if stage == 'request':
            user = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()
            if user:
                random_value = os.urandom(16)
                hash_object = hashlib.sha1(random_value)
                password_reset_token = hash_object.hexdigest()
                conn.execute('UPDATE user SET reset_token = ?, reset_token_created_at = ? WHERE email = ?', 
                             (password_reset_token, datetime.utcnow(), email))
                conn.commit()

                msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your password reset token is: {password_reset_token}'
                mail.send(msg)
                flash('An email with the password reset token has been sent.', 'info')
                return redirect(url_for('password_recovery', stage='verify', email=email))

            else:
                flash('No account associated with this email.', 'danger')

        elif stage == 'verify':
            token = request.form.get('token')
            user = conn.execute('SELECT * FROM user WHERE email = ? AND reset_token = ?', (email, token)).fetchone()

            if user:
                token_age = datetime.utcnow() - datetime.strptime(user['reset_token_created_at'], '%Y-%m-%d %H:%M:%S.%f')
                if token_age <= timedelta(minutes=5):
                    return redirect(url_for('password_recovery', stage='reset', email=email))
                else:
                    flash('Token has expired.', 'danger')
            else:
                flash('Invalid token.', 'danger')

        elif stage == 'reset':
            new_password = request.form.get('new_password')
            user = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()
            if user:
                is_valid, message = complexity_checks(new_password, config)
                if not is_valid:
                    flash(message, 'danger')
                else:
                    new_password_hashed, _ = hash_password_hmac(new_password, user['salt'])
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
