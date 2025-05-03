from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------ MODELS ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    secret_key = db.Column(db.String(256), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original = db.Column(db.Text, nullable=False)
    encrypted = db.Column(db.Text, nullable=False)
    decrypted = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ HELPERS ------------------

def generate_secret_key():
    """Generate a Fernet-compatible secret key."""
    key = Fernet.generate_key()
    return key.decode()  # Return the key as a base64-encoded string

def get_fernet(key_str):
    """Return a Fernet object initialized with the provided secret key."""
    try:
        return Fernet(key_str.encode())  # Fernet expects the key as bytes
    except ValueError:
        flash("Invalid Secret Key! Please ensure the key is valid.", "error")
        return None

def is_valid_base64(key):
    """Check if a string is a valid base64 URL-safe encoded key."""
    try:
        base64.urlsafe_b64decode(key)
        return True
    except (ValueError, TypeError):
        return False

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        gender = request.form['gender']
        hashed_password = generate_password_hash(password)
        secret_key = generate_secret_key()

        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('register'))

        new_user = User(email=email, password=hashed_password, gender=gender, secret_key=secret_key)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('register_success', secret=secret_key))

    return render_template('register.html')

@app.route('/register_success')
def register_success():
    secret = request.args.get('secret')
    return render_template('register_success.html', secret=secret)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('encrypt_decrypt'))
        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
def encrypt_decrypt():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    encrypted = decrypted = None

    if request.method == 'POST':
        text = request.form['text']
        secret_key = request.form['secret_key']

        # Validate the secret key
        if not is_valid_base64(secret_key):
            flash("Invalid Secret Key! Please enter a valid base64 URL-safe key.", "error")
            return redirect(url_for('encrypt_decrypt'))

        fernet = get_fernet(secret_key)
        if fernet:
            encrypted = fernet.encrypt(text.encode()).decode()
            decrypted = fernet.decrypt(encrypted.encode()).decode()

            msg = Message(
                user_id=user.id,
                original=text,
                encrypted=encrypted,
                decrypted=decrypted
            )
            db.session.add(msg)
            db.session.commit()

    messages = Message.query.filter_by(user_id=user.id).order_by(Message.timestamp.desc()).all()
    return render_template('encrypt_decrypt.html', encrypted=encrypted, decrypted=decrypted, user=user, messages=messages)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    messages = Message.query.filter_by(user_id=user_id).order_by(Message.timestamp.desc()).all()
    return render_template('dashboard.html', messages=messages)

@app.route('/delete/<int:message_id>')
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    message = Message.query.get_or_404(message_id)
    if message.user_id == session['user_id']:
        db.session.delete(message)
        db.session.commit()

    return redirect(url_for('dashboard'))

# ------------------ INIT DB ------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
