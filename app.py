from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from flask_migrate import Migrate
import redis
import datetime
import logging

app = Flask(__name__)

# PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/auth_db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# Redis Configuration
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# MongoDB Configuration
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client['auth_logs']
login_logs = mongo_db['login_attempts']

# Security Configurations
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

# User Model with Role-Based Access Control
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def __init__(self, username, password, role):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role

# Register User
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user = User(data['username'], data['password'], data.get('role', 'user'))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

# Login User
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        login_logs.insert_one({"username": user.username, "timestamp": datetime.datetime.utcnow()})
        redis_client.setex(f"session:{user.username}", 3600, access_token)
        return jsonify({"access_token": access_token}), 200
    else:
        login_logs.insert_one({"username": data['username'], "timestamp": datetime.datetime.utcnow(), "failed": True})
        return jsonify({"message": "Invalid credentials"}), 401

# Protected Route with Role-Based Access Control
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    return jsonify({"message": "Welcome Admin!"})

# Intrusion Detection System (Basic)
@app.before_request
def detect_intrusion():
    ip = request.remote_addr
    if redis_client.exists(f"block:{ip}"):
        return jsonify({"message": "Access blocked due to suspicious activity"}), 403
    
    failed_attempts = login_logs.count_documents({"username": request.json.get('username', ''), "failed": True})
    if failed_attempts >= 5:
        redis_client.setex(f"block:{ip}", 3600, "blocked")
        return jsonify({"message": "Too many failed attempts. Access blocked."}), 403

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
