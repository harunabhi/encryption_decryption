from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///harun.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# --------- Simple Models ---------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(10))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    original = db.Column(db.Text, nullable=False)
    encrypted = db.Column(db.Text, nullable=False)
    decrypted = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --------- Create Database ---------

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()      # Remove old tables (if any)
        db.create_all()    # Create new tables
        print("Fresh simple database 'harun.db' created.")
