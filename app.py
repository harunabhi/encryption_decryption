from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)
app.secret_key = '1234'  # Set fixed secret key for Flask sessions

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///harun.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --------- Create Database ---------
# Drop all tables and recreate them with the updated schema (for development)
with app.app_context():
    db.drop_all()      # Drop the old tables
    db.create_all()    # Recreate the tables with the updated schema
    print("Database recreated with secret_key column.")  # Print message

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    secret_key = db.Column(db.String(255), nullable=False)  # Store user's secret key
    messages = db.relationship('Message', backref='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def set_secret_key(self, secret_key):
        self.secret_key = secret_key

    def get_secret_key(self):
        return self.secret_key

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
# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        gender = request.form['gender']

        # Generate a secret key for the user
        secret_key = Fernet.generate_key().decode()  # Store as a string

        if User.query.filter_by(email=email).first():
            return "Email already exists"
        
        user = User(email=email, password=password, gender=gender, secret_key=secret_key)
        db.session.add(user)
        db.session.commit()

        # Show the secret key to the user after successful registration
        return render_template('register_success.html', secret_key=secret_key)  # Pass secret_key to the template
    
    return render_template('register.html')


# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['secret_key'] = user.get_secret_key()  # Store user's secret key in session
            return redirect(url_for('encrypt_decrypt'))  # Redirect directly to encrypt/decrypt page
        
        return "Invalid credentials"
    
    return render_template('login.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Route: Encrypt/Decrypt (Main page after login)
from cryptography.fernet import Fernet
import base64

# Route: Encrypt/Decrypt (Main page after login)
@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
def encrypt_decrypt():
    encrypted = None
    decrypted = None
    messages = []  # Start with an empty list for messages

    # Ensure user is logged in
    if 'user_id' not in session or 'secret_key' not in session:
        return redirect(url_for('login'))

    # Retrieve the secret key from the session
    secret_key = session['secret_key'].encode()  # Convert back to bytes

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        message = request.form.get('message')
        input_secret_key = request.form.get('input_secret_key')

        if message and input_secret_key:
            try:
                # Validate the input secret key
                try:
                    fernet_key = base64.urlsafe_b64decode(input_secret_key.encode())
                    if len(fernet_key) != 32:
                        raise ValueError("Invalid key length. It must be 32 bytes.")
                except Exception as e:
                    return f"Invalid secret key format. Ensure it is a valid base64 URL-safe 32-byte key. Error: {e}"

                # Use the user-inputted secret key
                fernet = Fernet(input_secret_key.encode())
                encrypted = fernet.encrypt(message.encode())
                decrypted = fernet.decrypt(encrypted).decode()

                # Save the encrypted and decrypted messages in the database
                msg = Message(
                    user_id=user.id,
                    original=message,
                    encrypted=encrypted.decode(),
                    decrypted=decrypted,
                    timestamp=datetime.utcnow()
                )
                db.session.add(msg)
                db.session.commit()

                messages = [encrypted.decode()]  # Store the encrypted message in the list
            except Exception as e:
                return f"Error: {e}"

    return render_template(
        'encrypt_decrypt.html',
        encrypted=encrypted,
        decrypted=decrypted,
        messages=messages,  # Pass an empty list if there are no messages
        secret_key=secret_key.decode()  # Convert to string for template display
    )

# Route: Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    messages = Message.query.filter_by(user_id=user.id).all()
    
    return render_template('dashboard.html', user=user, messages=messages)

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
    return redirect(url_for('encrypt_decrypt'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
