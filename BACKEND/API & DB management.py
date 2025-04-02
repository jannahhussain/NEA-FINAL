from flask import Flask, jsonify, request, session
from flask_cors import CORS
import os
import sqlite3
import bcrypt
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import pytest
import json

#initialising flask
app = Flask(__name__)

# Enabling Cross-Origin Resource Sharing
CORS(app)

# Config settings
app.config['DEBUG'] = True  # Enabling debug mode(for development)
app.config['PORT'] = 5000  # Port number for the server
app.config['HOST'] = '127.0.0.1'  # Localhost
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'Server is running'}), 200

# Error handling for 404 - Not Found
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

# Error handling for 500 - Internal Server Error
@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# Root route
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Localhost Application'}), 200

# Start the server
if __name__ == '__main__':
    try:
        print("Starting the server...")
        app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'])
    except Exception as e:
        print(f"Error starting server: {e}")

#///////////////////////////////////////////////////////////////////////////////////

# Database setup function
def connect_db():
    conn = sqlite3.connect('app_database.db')
    return conn

# Helper functions(for password hashing and verification)
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)

# User Registration (POST)
@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not username or not password or not email:
            return jsonify({"error": "Missing fields"}), 400

        hashed_password = hash_password(password)
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", 
                       (username, hashed_password, email))
        conn.commit()
        conn.close()

        logging.info(f"New user registered: {username}")
        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        logging.error(f"Error registering user: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# User Login (POST)
@app.route('/login', methods=['POST'])
def login_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Missing fields"}), 400

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result and verify_password(password, result[0]):
            conn.close()
            logging.info(f"User {username} logged in successfully.")
            return jsonify({"message": "Login successful"}), 200
        else:
            conn.close()
            logging.warning(f"Failed login attempt for {username}.")
            return jsonify({"error": "Invalid username or password"}), 401

    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Send Message (POST)
@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        data = request.get_json()
        sender_username = data.get('sender_username')
        receiver_username = data.get('receiver_username')
        content = data.get('content')

        if not sender_username or not receiver_username or not content:
            return jsonify({"error": "Missing fields"}), 400

        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (sender_username,))
        sender_id = cursor.fetchone()
        cursor.execute("SELECT id FROM users WHERE username = ?", (receiver_username,))
        receiver_id = cursor.fetchone()

        if not sender_id or not receiver_id:
            conn.close()
            return jsonify({"error": "Invalid sender or receiver"}), 404

        cursor.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                       (sender_id[0], receiver_id[0], content))
        conn.commit()
        conn.close()

        logging.info(f"Message from {sender_username} to {receiver_username} sent.")
        return jsonify({"message": "Message sent successfully"}), 201

    except Exception as e:
        logging.error(f"Error sending message: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Notifications (GET)
@app.route('/notifications', methods=['GET'])
def get_notifications():
    try:
        username = request.args.get('username')

        if not username:
            return jsonify({"error": "Username is required"}), 400

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notifications WHERE username = ?", (username,))
        notifications = cursor.fetchall()
        conn.close()

        if notifications:
            return jsonify({"notifications": notifications}), 200
        else:
            return jsonify({"message": "No notifications found"}), 404

    except Exception as e:
        logging.error(f"Error fetching notifications: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# User Profile (GET)
@app.route('/profile', methods=['GET'])
def get_user_profile():
    try:
        username = request.args.get('username')

        if not username:
            return jsonify({"error": "Username is required"}), 400

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({
                "id": user[0],
                "username": user[1],
                "email": user[2]
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        logging.error(f"Error fetching user profile: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Update User Profile (PUT)
@app.route('/update_profile', methods=['PUT'])
def update_user_profile():
    try:
        data = request.get_json()
        username = data.get('username')
        new_email = data.get('new_email')

        if not username or not new_email:
            return jsonify({"error": "Missing fields"}), 400

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, username))
        conn.commit()
        conn.close()

        logging.info(f"User {username} updated their profile.")
        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        logging.error(f"Error updating user profile: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Error handling for 404 and 500 errors
@app.errorhandler(404)
def page_not_found(error):
    return jsonify({"error": "Page not found"}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)

#///////////////////////////////////////////////////////////////////////////////////

# Configuring the SQLite database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initializing SQLAlchemy and Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Defining User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')  # Default role is 'user'

    messages_sent = db.relationship('Message', backref='sender', lazy=True)
    messages_received = db.relationship('Message', backref='receiver', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

# Defining Message model
class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f'<Message {self.id}>'

# Defining Notification model
class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Notification {self.id}>'

# Initializing the database
@app.before_first_request
def create_tables():
    db.create_all()

# Creating a simple route to check if the models are working
@app.route('/setup', methods=['GET'])
def setup_db():
    try:
        # Checking if tables are created
        user_count = User.query.count()
        return f"Database setup successful. Total users: {user_count}", 200
    except Exception as e:
        return f"Error setting up database: {str(e)}", 500

#///////////////////////////////////////////////////////////////////////////////////

# Initializing SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Defining User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')

    def __repr__(self):
        return f'<User {self.username}>'

# Helper function(to verify token)
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_function

# User registration endpoint
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists!'}), 400
    
    hashed_password = generate_password_hash(password, method='bcrypt')
    new_user = User(username=username, email=email, password_hash=hashed_password)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully!'}), 201

# User login endpoint
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'message': 'Login successful!', 'token': token})

# User logout endpoint
@app.route('/logout', methods=['POST'])
@token_required
def logout_user(current_user):
    session.clear()  # Clear session data
    return jsonify({'message': 'Logged out successfully!'})

# Route to get user profile (only if logged in)
@app.route('/profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role
    })

# Start Flask app
if __name__ == '__main__':
    app.run(debug=True)

#///////////////////////////////////////////////////////////////////////////////////


from app import app, User, db

# API Documentation using Swagger
@app.route('/swagger', methods=['GET'])
def swagger_docs():
    docs = {
        "swagger": "2.0",
        "info": {
            "title": "API Documentation",
            "version": "1.0.0",
            "description": "API for user management, messaging, and notifications."
        },
        "paths": {
            "/register": {
                "post": {
                    "summary": "User registration",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "description": "User data",
                            "required": True,
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "email": {"type": "string"},
                                    "password": {"type": "string"}
                                }
                            }
                        }
                    ],
                    "responses": {
                        "201": {
                            "description": "User created successfully"
                        },
                        "400": {
                            "description": "User already exists"
                        }
                    }
                }
            },
            "/login": {
                "post": {
                    "summary": "User login",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "description": "User login data",
                            "required": True,
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"}
                                }
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Login successful, JWT token returned"
                        },
                        "401": {
                            "description": "Invalid credentials"
                        }
                    }
                }
            }
        }
    }
    return jsonify(docs)


# Unit Tests using PyTest

def test_register_user(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    assert response.status_code == 201
    assert 'User created successfully' in response.get_json()['message']

def test_login_user(client):
    # First, register a user
    client.post('/register', json={
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    
    # Now, log in with the registered user credentials
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert 'token' in response.get_json()

def test_invalid_login(client):
    response = client.post('/login', json={
        'username': 'invaliduser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert 'Invalid credentials' in response.get_json()['message']

def test_missing_field_registration(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 400
    assert 'Missing field' in response.get_json()['message']


# Run the Flask app in testing mode
if __name__ == '__main__':
    app.run(debug=True)
