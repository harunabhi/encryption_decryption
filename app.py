from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///harun.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Changed from username to email
    password = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    messages = db.relationship('Message', backref='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original = db.Column(db.Text, nullable=False)
    encrypted = db.Column(db.Text, nullable=False)
    decrypted = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Route: Home → redirect
@app.route('/')
def home():
    return redirect(url_for('login'))

# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']  # Changed from username to email
        password = generate_password_hash(request.form['password'])
        gender = request.form['gender']

        # Check if email already exists
        if User.query.filter_by(email=email).first():  # Check email instead of username
            return "Email already exists"
        
        # Create new user
        user = User(email=email, password=password, gender=gender)
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))  # Redirect to login page after registration
    
    return render_template('register.html')


# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']  # Use email instead of username
        password = request.form['password']
        user = User.query.filter_by(email=email).first()  # Authenticate using email
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Route: Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    encrypted = decrypted = None
    if request.method == 'POST':
        message = request.form['message']

        try:
            # Use the fixed secret key "6969" for encryption
            secret_key = '6969'

            # Ensure the key is 32 bytes long by padding or trimming it
            secret_key = secret_key.ljust(32, '0')[:32]
            key = base64.urlsafe_b64encode(secret_key.encode())  # Encoding it to the base64 format
            fernet = Fernet(key)
            
            # Encrypt and Decrypt the message
            encrypted = fernet.encrypt(message.encode()).decode()
            decrypted = fernet.decrypt(encrypted.encode()).decode()

            # Save the message in the database
            msg = Message(
                user_id=session['user_id'],
                original=message,
                encrypted=encrypted,
                decrypted=decrypted
            )
            db.session.add(msg)
            db.session.commit()

        except Exception as e:
            return f"Encryption failed: {str(e)}"  # Handle errors gracefully

    messages = Message.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', encrypted=encrypted, decrypted=decrypted, messages=messages)

# Route: Delete message
@app.route('/delete/<int:id>')
def delete(id):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    msg = Message.query.get_or_404(id)
    if msg.user_id != session['user_id']:
        return "Unauthorized"
    db.session.delete(msg)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
