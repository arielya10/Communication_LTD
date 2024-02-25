from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

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