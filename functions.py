import hmac
import hashlib
import os
import re
import sqlite3

DATABASE = 'instance/site.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This allows accessing columns by name
    return conn

def shift_previous_passwords(user_id, new_password):
    conn = get_db_connection()
    user_record = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    if not user_record:
        conn.close()
        return False, "User not found."
    if (new_password == user_record['password'] or
       new_password == user_record['previous_password_1'] or
       new_password == user_record['previous_password_2'] or
       new_password == user_record['previous_password_3']):
        conn.close()
        return False, "New password must be different from the previous one."
    # Update user's password and shift the previous passwords
    conn.execute('UPDATE user SET password = ?, previous_password_1 = ?, previous_password_2 = ?, previous_password_3 = ? WHERE id = ?', 
             (new_password, user_record['password'], user_record['previous_password_1'], user_record['previous_password_2'], user_id))
    conn.commit()
    conn.close()
    return True, ''

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
def complexity_checks(new_password, config):  
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

    return True, ''

# Email format validation
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