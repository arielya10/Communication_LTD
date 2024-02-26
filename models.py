import sqlite3


def get_db_connection():
    conn = sqlite3.connect('instance/site.db')
    conn.row_factory = sqlite3.Row  # This allows accessing columns by name
    return conn

def clear_all_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Delete all data from tables
    cursor.execute('DELETE FROM customer')
    cursor.execute('DELETE FROM user')
    
    conn.commit()
    conn.close()
    print("All data cleared.")

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        previous_password_1 TEXT,
        previous_password_2 TEXT,
        previous_password_3 TEXT,
        login_attempts INTEGER DEFAULT 0,
        must_reset_password BOOLEAN DEFAULT FALSE,
        reset_token TEXT,
        reset_token_created_at TEXT,
        salt TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS customer (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        lastname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user (id)
    )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")