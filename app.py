import bcrypt
import os
import certifi
import pandas as pd
import random
import secrets
import string
import sys
import jwt
import functools
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from gridfs import GridFS
from bson import ObjectId
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from io import BytesIO
from dotenv import load_dotenv

load_dotenv()
# --- Flask App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
# A more robust CORS configuration
# Ensure TLS verification uses an up-to-date CA bundle (fixes SSL errors on some Windows setups)
os.environ.setdefault('SSL_CERT_FILE', certifi.where())
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# --- CRITICAL CONFIGURATION ---
# Use environment variables for Railway deployment, fallback to local values
MONGO_URI = os.getenv('MONGODB_URI', "mongodb+srv://testuser:testpassword123@sps-cluster.epkt9c1.mongodb.net/?retryWrites=true&w=majority&appName=sps-cluster&tlsAllowInvalidCertificates=true")
DB_NAME = "StudentProgressionDB" 
# --- ACTION REQUIRED: PASTE YOUR NEW, VALID SENDGRID API KEY HERE ---
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', 'SG.your-sendgrid-api-key-here')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'gandharvacjc@gmail.com') # This MUST be a "Verified Sender" in your SendGrid account
FROM_NAME = 'SPS Admin - GIT'

# --- JWT Configuration ---
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(64))  # Generate secure random key
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 days

# --- Rate Limiting Configuration ---
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# --- Initial Health Check ---
if 'PASTE_YOUR' in SENDGRID_API_KEY:
    print("CRITICAL ERROR: The SendGrid API key is still a placeholder. Update it in app.py before running.")
    sys.exit(1)

# --- Database Connection ---
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    client.admin.command('ismaster')
    print("SUCCESS: Successfully connected to MongoDB Atlas!")
except Exception as e:
    print(f"ERROR: DATABASE ERROR: Could not connect to MongoDB. Full error: {e}")
    sys.exit(1)

# --- Admin Setup Command ---
def create_admin_user():
    """Creates or updates the default admin user."""
    print("--- Running Admin Setup ---")
    users_collection = db["users"]
    hashed_password = bcrypt.hashpw("Admin@123".encode('utf-8'), bcrypt.gensalt())
    users_collection.update_one(
        {"username": "admin"},
        {"$set": {"password": hashed_password, "role": "admin", "email": "admin@git-india.edu.in"}},
        upsert=True
    )
    print("SUCCESS: Admin user 'admin' created/updated successfully with password 'Admin@123'.")

# --- JWT Token Functions ---
def generate_access_token(username, role='faculty'):
    """Generate JWT access token."""
    payload = {
        'username': username,
        'role': role,
        'type': 'access',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def generate_refresh_token(username):
    """Generate JWT refresh token."""
    payload = {
        'username': username,
        'type': 'refresh',
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """Verify JWT token and return payload."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --- Authentication Decorator ---
def require_auth(f):
    """Decorator to require authentication for API endpoints."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip auth for OPTIONS requests
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"message": "Authentication required. Please login."}), 401
        
        # Extract token from "Bearer <token>"
        try:
            token = auth_header.split(' ')[1] if ' ' in auth_header else auth_header
        except IndexError:
            return jsonify({"message": "Invalid authorization format. Use 'Bearer <token>'."}), 401
        
        # Verify token
        payload = verify_token(token)
        if not payload or payload.get('type') != 'access':
            return jsonify({"message": "Invalid or expired token. Please login again."}), 401
        
        # Check if user still exists
        user = db.users.find_one({"username": payload['username']})
        if not user:
            return jsonify({"message": "User not found. Please login again."}), 401
        
        # Store user info in Flask's g object for use in route
        g.current_user = {
            'username': payload['username'],
            'role': payload.get('role', 'faculty')
        }
        
        return f(*args, **kwargs)
    return decorated_function

# --- Block direct .html access middleware ---
@app.before_request
def block_html_access():
    """Block all direct .html file access before processing the request."""
    # Get the requested path
    path = request.path
    
    # Allow OPTIONS requests for CORS
    if request.method == 'OPTIONS':
        return None
    
    # If path ends with .html (case insensitive), return 404
    if path.lower().endswith('.html'):
        return app.send_static_file('404.html'), 404
    
    # Allow all other requests to proceed
    return None

# --- API Endpoints ---

@app.route('/api/admin/login', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")  # Rate limit admin login
def admin_login():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({"message": "Password is required"}), 400
    
    admin_doc = db.users.find_one({"username": "admin", "role": "admin"})
    if admin_doc and bcrypt.checkpw(password.encode('utf-8'), admin_doc['password']):
        # Generate tokens for admin
        access_token = generate_access_token("admin", "admin")
        refresh_token = generate_refresh_token("admin")
        
        db.refresh_tokens.update_one(
            {"username": "admin"},
            {"$set": {
                "token": refresh_token,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
            }},
            upsert=True
        )
        
        return jsonify({
            "message": "Admin authentication successful!",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }), 200
    return jsonify({"message": "Invalid admin credentials"}), 401

@app.route('/api/refresh-token', methods=['POST', 'OPTIONS'])
def refresh_token():
    """Refresh access token using refresh token."""
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    refresh_token_value = data.get('refresh_token')
    
    if not refresh_token_value:
        return jsonify({"message": "Refresh token is required"}), 400
    
    # Verify refresh token
    payload = verify_token(refresh_token_value)
    if not payload or payload.get('type') != 'refresh':
        return jsonify({"message": "Invalid or expired refresh token"}), 401
    
    username = payload.get('username')
    
    # Verify token exists in database (can be revoked)
    stored_token = db.refresh_tokens.find_one({"username": username, "token": refresh_token_value})
    if not stored_token:
        return jsonify({"message": "Refresh token has been revoked"}), 401
    
    # Check expiration
    expires_at = stored_token.get('expires_at')
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if isinstance(expires_at, datetime) and datetime.now(timezone.utc) > expires_at:
        db.refresh_tokens.delete_one({"username": username})
        return jsonify({"message": "Refresh token expired"}), 401
    
    # Generate new access token
    user = db.users.find_one({"username": username})
    if not user:
        return jsonify({"message": "User not found"}), 401
    
    access_token = generate_access_token(username, user.get('role', 'faculty'))
    
    return jsonify({
        "access_token": access_token,
        "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }), 200

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@require_auth
def logout():
    """Logout user and revoke refresh token."""
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    username = g.current_user['username']
    
    # Revoke refresh token
    db.refresh_tokens.delete_one({"username": username})
    
    # Clear failed login attempts
    db.login_attempts.delete_one({"_id": f"login_failed:{username}"})
    
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/verify-token', methods=['GET', 'OPTIONS'])
@require_auth
def verify_token_endpoint():
    """Verify if current token is valid."""
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    return jsonify({
        "valid": True,
        "user": g.current_user
    }), 200

@app.route('/api/upload-faculty', methods=['POST', 'OPTIONS'])
@require_auth
def upload_faculty_list():
    # Verify admin role
    if g.current_user.get('role') != 'admin':
        return jsonify({"message": "Admin access required"}), 403
    if 'file' not in request.files: return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    try:
        df = pd.read_excel(file)
        if 'College Mail' not in df.columns or 'Name of Faculty' not in df.columns:
            return jsonify({"message": "Excel must contain 'College Mail' and 'Name of Faculty' columns."}), 400
        
        faculty_collection = db.authorized_faculty
        count = 0
        for _, row in df.iterrows():
            email, name = row['College Mail'], row['Name of Faculty']
            if not isinstance(email, str) or "@" not in email: continue
            
            new_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            faculty_collection.update_one(
                {"email": email},
                {"$set": {
                    "name": name,
                    "registration_key": new_key,
                    "key_expires_at": datetime.now(timezone.utc) + timedelta(hours=2),
                    "is_registered": False
                }},
                upsert=True
            )
            count += 1
        return jsonify({"message": f"Successfully processed {count} faculty records."}), 200
    except Exception as e:
        return jsonify({"message": f"An error occurred: {e}"}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")  # Rate limit: 5 login attempts per minute
def login_user():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400
    
    # Check for rate limiting in MongoDB (optional - track failed attempts)
    failed_attempts_key = f"login_failed:{username}"
    failed_doc = db.login_attempts.find_one({"_id": failed_attempts_key})
    
    if failed_doc:
        attempts = failed_doc.get('count', 0)
        last_attempt = failed_doc.get('last_attempt')
        if attempts >= 5:
            if last_attempt:
                last_time = last_attempt if isinstance(last_attempt, datetime) else datetime.fromisoformat(last_attempt.replace('Z', '+00:00')) if isinstance(last_attempt, str) else datetime.now(timezone.utc)
                if isinstance(last_time, datetime) and last_time.tzinfo is None:
                    last_time = last_time.replace(tzinfo=timezone.utc)
                lockout_duration = timedelta(minutes=15)
                if isinstance(last_time, datetime) and datetime.now(timezone.utc) - last_time < lockout_duration:
                    remaining = lockout_duration - (datetime.now(timezone.utc) - last_time)
                    minutes = int(remaining.total_seconds() / 60)
                    return jsonify({"message": f"Account temporarily locked. Try again in {minutes} minutes."}), 429
    
    user = db.users.find_one({"username": username})
    if user and 'password' in user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        # Successful login - generate tokens
        access_token = generate_access_token(username, user.get('role', 'faculty'))
        refresh_token = generate_refresh_token(username)
        
        # Store refresh token in database (for revocation if needed)
        db.refresh_tokens.update_one(
            {"username": username},
            {"$set": {
                "token": refresh_token,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
            }},
            upsert=True
        )
        
        # Clear failed attempts
        db.login_attempts.delete_one({"_id": failed_attempts_key})
        
        # Update last login
        db.users.update_one(
            {"username": username},
            {"$set": {"last_login": datetime.now(timezone.utc)}}
        )
        
        return jsonify({
            "message": "Login successful!",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
            "user": {
                "username": username,
                "role": user.get('role', 'faculty'),
                "email": user.get('email', '')
            }
        }), 200
    
    # Failed login - track attempts
    if failed_doc:
        db.login_attempts.update_one(
            {"_id": failed_attempts_key},
            {"$set": {
                "count": attempts + 1,
                "last_attempt": datetime.now(timezone.utc)
            }},
            upsert=True
        )
    else:
        db.login_attempts.insert_one({
            "_id": failed_attempts_key,
            "count": 1,
            "last_attempt": datetime.now(timezone.utc)
        })
    
    return jsonify({"message": "Invalid username or password"}), 401

@app.route('/api/send-registration-code', methods=['POST', 'OPTIONS'])
def send_registration_code():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    
    if db.users.find_one({"email": email}):
        return jsonify({"message": "An account with this email already exists."}), 409
    
    faculty = db.authorized_faculty.find_one({"email": email})
    if not faculty:
        return jsonify({"message": "Faculty not found. Kindly contact admin."}), 403
    if faculty.get("is_registered", False):
        return jsonify({"message": "This email has already been used to create an account."}), 409
    
    # Normalize and validate key expiration time to UTC-aware datetime
    now_utc = datetime.now(timezone.utc)
    key_expires_at = faculty.get('key_expires_at')
    if isinstance(key_expires_at, str):
        try:
            # Support ISO strings including those ending with 'Z'
            key_expires_at = datetime.fromisoformat(key_expires_at.replace('Z', '+00:00'))
        except Exception:
            key_expires_at = None
    if isinstance(key_expires_at, datetime) and key_expires_at.tzinfo is None:
        key_expires_at = key_expires_at.replace(tzinfo=timezone.utc)
    if not isinstance(key_expires_at, datetime) or now_utc > key_expires_at:
        # Auto-regenerate a fresh registration key valid for 2 hours
        new_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        db.authorized_faculty.update_one(
            {"email": email},
            {"$set": {"registration_key": new_key, "key_expires_at": now_utc + timedelta(hours=2), "is_registered": False}}
        )
        faculty = db.authorized_faculty.find_one({"email": email})
        
    v_code = secrets.token_hex(3).upper()
    db.verifications.update_one(
        {"email": email}, 
        {"$set": {"code": v_code, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)}}, 
        upsert=True
    )
    print(f"🔐 Generated verification code for {email}: {v_code}")
    
    html_content = f"<p>Hello {faculty['name']},</p><p>Your verification code is: <strong>{v_code}</strong></p><p>Your registration key is: <strong>{faculty['registration_key']}</strong></p>"
    message = Mail(from_email=(FROM_EMAIL, FROM_NAME), to_emails=email, subject="SPS Account Verification", html_content=html_content)
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"SUCCESS: SendGrid email sent! Status: {response.status_code}")
        return jsonify({"message": "Verification code and key sent to your email."}), 200
    except Exception as e:
        print(f"ERROR: SENDGRID ERROR (continuing with dev flow): {e}")
        # Allow proceeding during development by returning 200 with the code
        return jsonify({
            "message": "Email could not be sent. Use the on-screen code to continue.",
            "dev_code": v_code
        }), 200

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    v_doc = db.verifications.find_one({"email": data.get('email'), "code": data.get('code').upper()})
    # Normalize verification expiry
    expires_at = None
    if v_doc and 'expires_at' in v_doc:
        expires_at = v_doc['expires_at']
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            except Exception:
                expires_at = None
        if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not v_doc or not isinstance(expires_at, datetime) or datetime.now(timezone.utc) > expires_at:
        return jsonify({"message": "Invalid or expired verification code."}), 400

    faculty_doc = db.authorized_faculty.find_one({"email": data.get('email'), "registration_key": data.get('registration_key')})
    if not faculty_doc:
        return jsonify({"message": "The registration key is incorrect, expired, or used."}), 403
        
    hashed_pw = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt())
    db.users.insert_one({
        "username": data.get('username'), "password": hashed_pw, "email": data.get('email'), "role": "faculty"
    })
    
    db.authorized_faculty.update_one(
        {"email": data.get('email')},
        {"$set": {"last_used_key": data.get('registration_key'), "is_registered": True}, "$unset": {"registration_key": "", "key_expires_at": ""}}
    )
    db.verifications.delete_one({"email": data.get('email')})
    
    return jsonify({"message": "Account created successfully! You can now log in."}), 201

# --- Password Reset Flow ---
@app.route('/api/send-reset-code', methods=['POST', 'OPTIONS'])
def send_reset_code():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({"message": "Email is required"}), 400
    user = db.users.find_one({"email": email})
    if not user:
        # Do not reveal if email exists
        return jsonify({"message": "If the email exists, a reset code has been sent."}), 200
    reset_code = secrets.token_hex(3).upper()
    db.password_resets.update_one(
        {"email": email},
        {"$set": {"code": reset_code, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)}},
        upsert=True
    )
    print(f"Generated password reset code for {email}: {reset_code}")
    html_content = f"<p>Hello,</p><p>Your password reset code is: <strong>{reset_code}</strong></p><p>This code expires in 10 minutes.</p>"
    message = Mail(from_email=(FROM_EMAIL, FROM_NAME), to_emails=email, subject="SPS Password Reset Code", html_content=html_content)
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"SUCCESS: SendGrid reset email sent! Status: {response.status_code}")
        return jsonify({"message": "A reset code has been sent to your email."}), 200
    except Exception as e:
        print(f"ERROR: SENDGRID ERROR (reset, continuing with dev flow): {e}")
        return jsonify({"message": "Email could not be sent. Use the on-screen code to continue.", "dev_code": reset_code}), 200

@app.route('/api/verify-reset-code', methods=['POST', 'OPTIONS'])
def verify_reset_code():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    code = (data.get('code') or '').upper()
    doc = db.password_resets.find_one({"email": email, "code": code})
    if not doc:
        return jsonify({"message": "Invalid code."}), 400
    expires_at = doc.get('expires_at')
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        except Exception:
            expires_at = None
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not isinstance(expires_at, datetime) or datetime.now(timezone.utc) > expires_at:
        return jsonify({"message": "Code expired."}), 400
    return jsonify({"message": "Code verified."}), 200

@app.route('/api/reset-password', methods=['POST', 'OPTIONS'])
def reset_password():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    code = (data.get('code') or '').upper()
    new_password = data.get('new_password')
    doc = db.password_resets.find_one({"email": email, "code": code})
    if not doc:
        return jsonify({"message": "Invalid code."}), 400
    expires_at = doc.get('expires_at')
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        except Exception:
            expires_at = None
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not isinstance(expires_at, datetime) or datetime.now(timezone.utc) > expires_at:
        return jsonify({"message": "Code expired."}), 400
    if not new_password or len(new_password) < 6:
        return jsonify({"message": "Password must be at least 6 characters."}), 400
    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    db.users.update_one({"email": email}, {"$set": {"password": hashed_pw}})
    db.password_resets.delete_one({"email": email})
    return jsonify({"message": "Password reset successfully."}), 200

# --- User Profile APIs ---
@app.route('/api/user/<username>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@require_auth
def user_profile(username):
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    if request.method == 'GET':
        user = db.users.find_one({"username": username})
        if not user:
            return jsonify({"message": "User not found"}), 404
        return jsonify({"username": user.get('username'), "email": user.get('email')}), 200
    if request.method == 'PUT':
        data = request.get_json()
        new_username = (data or {}).get('new_username')
        if not new_username or not new_username.strip():
            return jsonify({"message": "New username is required"}), 400
        if db.users.find_one({"username": new_username}):
            return jsonify({"message": "Username already taken"}), 409
        res = db.users.update_one({"username": username}, {"$set": {"username": new_username}})
        if res.matched_count == 0:
            return jsonify({"message": "User not found"}), 404
        return jsonify({"message": "Profile updated successfully."}), 200
    if request.method == 'DELETE':
        res = db.users.delete_one({"username": username})
        db.verifications.delete_one({"email": username})
        if res.deleted_count == 0:
            return jsonify({"message": "User not found"}), 404
        return jsonify({"message": "Account deleted successfully."}), 200

@app.route('/api/change-password', methods=['POST', 'OPTIONS'])
@require_auth
def change_password():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    username = data.get('username')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    user = db.users.find_one({"username": username})
    if not user:
        return jsonify({"message": "User not found"}), 404
    if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
        return jsonify({"message": "Current password is incorrect"}), 400
    if not new_password or len(new_password) < 6:
        return jsonify({"message": "New password must be at least 6 characters"}), 400
    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    db.users.update_one({"_id": user['_id']}, {"$set": {"password": hashed_pw}})
    return jsonify({"message": "Password changed successfully."}), 200

# --- OTP-based Password Change Flow ---
@app.route('/api/send-password-change-otp', methods=['POST', 'OPTIONS'])
@require_auth
def send_password_change_otp():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    username = data.get('username')
    current_password = data.get('current_password')
    
    if not username or not current_password:
        return jsonify({"message": "Username and current password are required"}), 400
    
    user = db.users.find_one({"username": username})
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
        return jsonify({"message": "Current password is incorrect"}), 400
    
    # Generate OTP
    otp_code = secrets.token_hex(3).upper()
    db.password_change_otps.update_one(
        {"username": username},
        {"$set": {"code": otp_code, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)}},
        upsert=True
    )
    
    # Send OTP via email
    email = user.get('email')
    if email:
        html_content = f"<p>Hello,</p><p>Your password change verification code is: <strong>{otp_code}</strong></p><p>This code expires in 10 minutes.</p>"
        message = Mail(from_email=(FROM_EMAIL, FROM_NAME), to_emails=email, subject="SPS Password Change Verification", html_content=html_content)
        try:
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            print(f"SUCCESS: SendGrid password change OTP sent! Status: {response.status_code}")
        except Exception as e:
            print(f"ERROR: SENDGRID ERROR (password change OTP): {e}")
    
    print(f"Generated password change OTP for {username}: {otp_code}")
    return jsonify({"message": "Verification code sent to your email."}), 200

@app.route('/api/verify-password-change-otp', methods=['POST', 'OPTIONS'])
@require_auth
def verify_password_change_otp():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    username = data.get('username')
    code = (data.get('code') or '').upper()
    
    if not username or not code:
        return jsonify({"message": "Username and code are required"}), 400
    
    doc = db.password_change_otps.find_one({"username": username, "code": code})
    if not doc:
        return jsonify({"message": "Invalid code"}), 400
    
    expires_at = doc.get('expires_at')
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        except Exception:
            expires_at = None
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not isinstance(expires_at, datetime) or datetime.now(timezone.utc) > expires_at:
        return jsonify({"message": "Code expired"}), 400
    
    return jsonify({"message": "Code verified"}), 200

@app.route('/api/change-password-with-otp', methods=['POST', 'OPTIONS'])
@require_auth
def change_password_with_otp():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    
    if not username or not new_password:
        return jsonify({"message": "Username and new password are required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"message": "New password must be at least 6 characters"}), 400
    
    # Check if OTP was verified (exists in database)
    otp_doc = db.password_change_otps.find_one({"username": username})
    if not otp_doc:
        return jsonify({"message": "Please verify your identity first"}), 400
    
    # Update password
    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    db.users.update_one({"username": username}, {"$set": {"password": hashed_pw}})
    
    # Clean up OTP
    db.password_change_otps.delete_one({"username": username})
    
    return jsonify({"message": "Password changed successfully."}), 200

# --- New Password Change Flow for Settings Page ---
@app.route('/api/check-email', methods=['POST', 'OPTIONS'])
def check_email():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"message": "Email is required"}), 400
    
    # Check if email exists in authorized_faculty collection
    faculty = db.authorized_faculty.find_one({"email": email})
    if not faculty:
        return jsonify({"message": "Email not found in system"}), 404
    
    return jsonify({"message": "Email found"}), 200

@app.route('/api/send-password-otp', methods=['POST', 'OPTIONS'])
def send_password_otp():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"message": "Email is required"}), 400
    
    # Check if email exists in authorized_faculty
    faculty = db.authorized_faculty.find_one({"email": email})
    if not faculty:
        return jsonify({"message": "Email not found in system"}), 404
    
    # Generate OTP
    otp_code = secrets.token_hex(3).upper()
    db.password_resets.update_one(
        {"email": email},
        {"$set": {"code": otp_code, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)}},
        upsert=True
    )
    
    # Send OTP via email
    html_content = f"<p>Hello {faculty.get('name', 'User')},</p><p>Your password change verification code is: <strong>{otp_code}</strong></p><p>This code expires in 10 minutes.</p>"
    message = Mail(from_email=(FROM_EMAIL, FROM_NAME), to_emails=email, subject="SPS Password Change Verification", html_content=html_content)
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"SUCCESS: SendGrid password change OTP sent! Status: {response.status_code}")
        print(f"Generated password change OTP for {email}: {otp_code}")
        return jsonify({"message": "OTP sent successfully to your email."}), 200
    except Exception as e:
        # In development or if email provider fails, allow continuing by returning the code
        err_text = str(getattr(e, 'body', e))
        print(f"ERROR: SENDGRID ERROR (password change OTP): {err_text}")
        print(f"Generated password change OTP for {email}: {otp_code}")
        return jsonify({
            "message": "Email could not be sent. Use the on-screen code to continue.",
            "dev_code": otp_code,
            "reason": err_text
        }), 200

@app.route('/api/verify-password-otp', methods=['POST', 'OPTIONS'])
def verify_password_otp():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    code = (data.get('code') or '').upper()
    
    if not email or not code:
        return jsonify({"message": "Email and code are required"}), 400
    
    doc = db.password_resets.find_one({"email": email, "code": code})
    if not doc:
        return jsonify({"message": "Invalid code"}), 400
    
    expires_at = doc.get('expires_at')
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        except Exception:
            expires_at = None
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not isinstance(expires_at, datetime) or datetime.now(timezone.utc) > expires_at:
        return jsonify({"message": "Code expired"}), 400
    
    return jsonify({"message": "Code verified"}), 200

@app.route('/api/reset-password', methods=['POST', 'OPTIONS'])
def reset_password_new():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')
    
    if not email or not new_password:
        return jsonify({"message": "Email and new password are required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"message": "New password must be at least 6 characters"}), 400
    
    # Check if OTP was verified (exists in database)
    doc = db.password_resets.find_one({"email": email})
    if not doc:
        return jsonify({"message": "Please verify your identity first"}), 400
    
    # Update password for the user with this email
    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    db.users.update_one({"email": email}, {"$set": {"password": hashed_pw}})
    
    # Clean up OTP
    db.password_resets.delete_one({"email": email})
    
    return jsonify({"message": "Password changed successfully."}), 200

# --- Result File Management APIs ---

def build_master_and_summary():
    """Build master DataFrame and per-semester summary from latest GridFS excel files."""
    fs = GridFS(db)
    sem_keys = [f"sem{i}" for i in range(1, 9)]
    latest_docs = {sem: db.result_files.find_one({"semester": sem, "file_type": "excel"}, sort=[("uploaded_at", -1)]) for sem in sem_keys}
    import pandas as pd
    master = pd.DataFrame(columns=["Name", "Role"] + [f"Sem{i}" for i in range(1, 9)])
    cleared_set: set = set()
    summary_rows: list = []
    prev_names: set = set()

    for sem_index in range(1, 9):
        sem = f"sem{sem_index}"
        try:
            doc = latest_docs.get(sem)
            if not doc:
                summary_rows.append({"semester": sem, "total": 0, "without_backlog": 0, "with_backlog": 0, "left": 0, "avg_cgpa": None})
                continue

            grid_id = doc["file_id"]
            file_obj = fs.get(grid_id)
            data = file_obj.read()
            import io
            raw = pd.read_excel(io.BytesIO(data), header=None)
            header_row = None
            for i, row in raw.iterrows():
                row_up = [str(c).strip().upper() for c in row.tolist()]
                if "NAME" in row_up and ("CGPA" in row_up or "SGPA" in row_up or "GPA" in row_up):
                    header_row = i
                    break
            df = pd.read_excel(io.BytesIO(data), skiprows=header_row if header_row is not None else 0)
            df.columns = [str(c).strip().upper() for c in df.columns]
            # pick cgpa-like column
            cgpa_col = None
            for candidate in ["CGPA", "SGPA", "GPA"]:
                if candidate in df.columns:
                    cgpa_col = candidate
                    break
            if "NAME" not in df.columns or cgpa_col is None:
                raise ValueError("Required columns not found")

            df = df[["NAME", cgpa_col]].dropna(subset=["NAME"]).copy()
            df["NAME"] = df["NAME"].astype(str).str.strip().str.lstrip("/")
            df[cgpa_col] = df[cgpa_col].replace("--", pd.NA)

            sem_map = dict(zip(df["NAME"], df[cgpa_col]))
            names_in_file = set(df["NAME"]) 
            total_students = len(names_in_file)

            if sem_index == 1:
                df_out = pd.DataFrame({"Name": df["NAME"], "Role": "Regular"})
                for i in range(1, 9):
                    df_out[f"Sem{i}"] = pd.NA
                df_out[f"Sem{sem_index}"] = df[cgpa_col]
                master = pd.concat([master, df_out], ignore_index=True)
                cleared_set = set(df.loc[df[cgpa_col].notna(), "NAME"]) 
            elif sem_index == 2:
                eligible = cleared_set
                cleared_now = {n for n in eligible if n in sem_map and pd.notna(sem_map[n])}
                master.loc[master["Name"].isin(cleared_now), f"Sem{sem_index}"] = master["Name"].map(sem_map)
                cleared_set = cleared_now
            elif sem_index == 3:
                known_names = set(master["Name"]) 
                dse_names = [n for n in names_in_file if n not in known_names]
                if dse_names:
                    dse_rows = pd.DataFrame({"Name": dse_names, "Role": "DSE"})
                    for i in range(1, 9):
                        dse_rows[f"Sem{i}"] = pd.NA
                    master = pd.concat([master, dse_rows], ignore_index=True)
                eligible_regular = set(master.loc[master["Role"] == "Regular", "Name"]).intersection(cleared_set)
                regular_cleared = {n for n in eligible_regular if n in sem_map and pd.notna(sem_map[n])}
                dse_cleared = {n for n in dse_names if n in sem_map and pd.notna(sem_map[n])}
                master.loc[master["Name"].isin(regular_cleared | dse_cleared), f"Sem{sem_index}"] = master["Name"].map(sem_map)
                cleared_set = regular_cleared | dse_cleared
            else:
                eligible = cleared_set
                cleared_now = {n for n in eligible if n in sem_map and pd.notna(sem_map[n])}
                master.loc[master["Name"].isin(cleared_now), f"Sem{sem_index}"] = master["Name"].map(sem_map)
                cleared_set = cleared_now

            without_backlog = len(cleared_set)
            with_backlog = total_students - without_backlog
            left_students = len(prev_names - names_in_file) if sem_index > 1 else 0
            avg_cgpa = df[cgpa_col].dropna().astype(float).mean()
            summary_rows.append({
                "semester": sem,
                "total": total_students,
                "without_backlog": int(without_backlog),
                "with_backlog": int(with_backlog),
                "left": int(left_students),
                "avg_cgpa": round(float(avg_cgpa), 2) if pd.notna(avg_cgpa) else None
            })
            prev_names = names_in_file
        except Exception:
            # Append zeros for robustness if parsing fails
            summary_rows.append({"semester": sem, "total": 0, "without_backlog": 0, "with_backlog": 0, "left": 0, "avg_cgpa": None})

    return master, summary_rows


def _adjust_summary_for_export(master, summary_rows):
    """Apply export-only adjustments inspired by result_parser.py without affecting dashboard data.

    - Align Sem3 metrics to Sem4 student list if both are available
    - Set Sem4 "left" to 0 after alignment
    - Append combined averages (Sem1&Sem2, Sem3&Sem4, Sem5&Sem6, Sem7&Sem8)
    - Sort DSE students by first token of name (surname proxy) in the master sheet
    """
    import math
    # Clone rows to avoid mutating the dashboard data by reference
    rows = [dict(r) for r in summary_rows]

    # Helper map for easy access
    sem_to_row = { (r.get("semester") or "").lower(): r for r in rows }

    # Align Sem3 stats based on Sem4 name list if both exist
    try:
        sem3_key, sem4_key = "sem3", "sem4"
        if sem3_key in sem_to_row and sem4_key in sem_to_row:
            r3 = sem_to_row[sem3_key]
            r4 = sem_to_row[sem4_key]
            # Align Sem3 total to Sem4 total (names in Sem4 file), preserving Sem3 pass count
            sem3_total = int(r4.get("total") or 0)
            sem3_without_backlog = int(r3.get("without_backlog") or 0)
            sem3_with_backlog = max(0, sem3_total - sem3_without_backlog)
            r3["total"] = sem3_total
            r3["with_backlog"] = sem3_with_backlog
            # Set Sem4 left to 0 as per parser logic
            r4["left"] = 0
    except Exception:
        # Fail open; keep original if adjustment fails
        pass

    # Append combined averages
    def get_avg(label):
        row = sem_to_row.get(label)
        return row.get("avg_cgpa") if row else None

    combined_pairs = [("sem1", "sem2"), ("sem3", "sem4"), ("sem5", "sem6"), ("sem7", "sem8")]
    for a, b in combined_pairs:
        a_avg, b_avg = get_avg(a), get_avg(b)
        if a_avg is not None and b_avg is not None:
            combined_avg = round((float(a_avg) + float(b_avg)) / 2, 2)
            rows.append({
                "semester": f"{a.upper()}&{b.upper()} Combined Avg",
                "total": None,
                "without_backlog": None,
                "with_backlog": None,
                "left": None,
                "avg_cgpa": combined_avg,
            })

    # Sort DSE students by first token (surname proxy) after regulars in master
    try:
        if not master.empty and "Role" in master.columns and "Name" in master.columns:
            regular_df = master[master["Role"] == "Regular"]
            dse_df = master[master["Role"] == "DSE"].copy()
            if not dse_df.empty:
                dse_df["_surname_key"] = dse_df["Name"].astype(str).str.strip().str.split().str[0]
                dse_df = dse_df.sort_values(by="_surname_key").drop(columns=["_surname_key"])
                master = pd.concat([regular_df, dse_df], ignore_index=True)
    except Exception:
        pass

    return master, rows

def recompute_dashboard_summary():
    """Compute and store dashboard summary in MongoDB."""
    master, summary_rows = build_master_and_summary()
    # Apply same alignment and combined averages so dashboard matches export
    try:
        master, summary_rows = _adjust_summary_for_export(master, summary_rows)
    except Exception:
        pass
    # If no data, clear
    if not any((row.get('total') or 0) > 0 for row in summary_rows):
        db.dashboard_summary.replace_one({"_id": "summary"}, {"_id": "summary", "updated_at": datetime.now(timezone.utc), "semesters": [], "kpis": {}}, upsert=True)
        return

    # KPIs example (can be extended):
    # Preserve existing KPI overrides if present (from admissions upload)
    existing = db.dashboard_summary.find_one({"_id": "summary"}) or {}
    kpis = existing.get("kpis", {})
    # Always refresh computed fields available from results, but preserve uploaded overrides
    if "dse" not in kpis:  # Only compute if not manually uploaded
        kpis["dse"] = int(master.loc[master["Role"] == "DSE"].shape[0]) if not master.empty else 0
    if "successfully_completed" not in kpis:  # Only compute if not manually uploaded
        kpis["successfully_completed"] = int(master.dropna(subset=["Sem8"]).shape[0]) if "Sem8" in master.columns else 0

    db.dashboard_summary.replace_one(
        {"_id": "summary"},
        {"_id": "summary", "updated_at": datetime.now(timezone.utc), "semesters": summary_rows, "kpis": kpis},
        upsert=True
    )


@app.route('/api/upload-admissions-kpis', methods=['POST', 'OPTIONS'])
@require_auth
def upload_admissions_kpis():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    try:
        import pandas as pd
        # Read content once so we can both parse and store
        file_content = file.read()
        df = pd.read_excel(BytesIO(file_content))
        # Normalize headers
        df.columns = [str(c).strip().lower() for c in df.columns]
        # Flexible header aliases (case-insensitive; we already lower-cased)
        header_aliases = {
            'sanctioned_intake': ['sanctioned intake', 'sanctioned_intake', 'intake'],
            'total_admitted': ['total admitted', 'total_admitted', 'admitted'],
            'dse': ['dse', 'dse admitted', 'direct second year', 'dse intake', 'dse_overridden'],
            'successfully_completed': [
                'successfully passed without backlog',
                'successfully completed',
                'successfully completed (w/o kt)',
                'successfully completed without backlog',
                'without backlog',
                'passed without backlog'
            ]
        }

        def pick(col_keys):
            for key in col_keys:
                if key in df.columns:
                    return key
            return None

        row = df.iloc[0]
        sanctioned_col = pick(header_aliases['sanctioned_intake'])
        total_admitted_col = pick(header_aliases['total_admitted'])
        dse_col = pick(header_aliases['dse'])
        success_completed_col = pick(header_aliases['successfully_completed'])

        # Build overrides, treat missing optional columns gracefully
        overridden = {
            'sanctioned_intake': int(row[sanctioned_col]) if sanctioned_col and pd.notna(row[sanctioned_col]) else None,
            'total_admitted': int(row[total_admitted_col]) if total_admitted_col and pd.notna(row[total_admitted_col]) else None,
            'dse': int(row[dse_col]) if dse_col and pd.notna(row[dse_col]) else None,
            'successfully_completed': int(row[success_completed_col]) if success_completed_col and pd.notna(row[success_completed_col]) else None
        }

        if not sanctioned_col and not total_admitted_col and not dse_col and not success_completed_col:
            return jsonify({"message": "No recognized KPI headers found in the first row."}), 400
        # Merge into existing summary
        doc = db.dashboard_summary.find_one({"_id": "summary"}) or {"kpis": {}}
        kpis = doc.get('kpis', {})
        for k, v in overridden.items():
            if v is not None:
                kpis[k] = v
        
        # Store the source file into GridFS so it can be downloaded later
        fs = GridFS(db)
        grid_id = fs.put(BytesIO(file_content), filename=file.filename, file_type='intake', uploaded_at=datetime.now(timezone.utc))
        file_size = len(file_content)

        # Store the file metadata for upload tracking (with GridFS id)
        db.intake_files.insert_one({
            "file_id": grid_id,
            "filename": file.filename,
            "uploaded_at": datetime.now(timezone.utc),
            "kpis": overridden,
            "file_size": file_size
        })
        
        db.dashboard_summary.replace_one({"_id": "summary"}, {"_id": "summary", "updated_at": datetime.now(timezone.utc), "semesters": doc.get('semesters', []), "kpis": kpis}, upsert=True)
        return jsonify({"message": "Admissions KPIs uploaded successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Error parsing KPI file: {e}"}), 500


@app.route('/api/dashboard-summary', methods=['GET', 'OPTIONS'])
@require_auth
def get_dashboard_summary():
    # Always recompute so UI reflects latest alignment and metrics
    try:
        recompute_dashboard_summary()
    except Exception:
        pass
    doc = db.dashboard_summary.find_one({"_id": "summary"})
    if not doc:
        return jsonify({"message": "Summary not available"}), 404
    # Convert datetime to iso
    if doc.get("updated_at"):
        doc["updated_at"] = doc["updated_at"].isoformat()
    return jsonify(doc), 200


@app.route('/api/export-result-summary', methods=['GET', 'OPTIONS'])
@require_auth
def export_result_summary():
    """Generate and download the combined result summary Excel (master + summary)."""
    try:
        import pandas as pd
        master, summary_rows = build_master_and_summary()
        # Apply export-only adjustments to reflect result_parser.py behavior
        master, summary_rows = _adjust_summary_for_export(master, summary_rows)
        # Build summary dataframe
        summary_df = pd.DataFrame(summary_rows)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            master.to_excel(writer, sheet_name='Master', index=False)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        output.seek(0)
        from flask import Response
        return Response(
            output.read(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': 'attachment; filename="Result_Summary.xlsx"'}
        )
    except Exception as e:
        return jsonify({"message": f"Error generating export: {e}"}), 500
@app.route('/api/upload-result-file', methods=['POST', 'OPTIONS'])
@require_auth
def upload_result_file():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['file']
    semester = request.form.get('semester')
    file_type = request.form.get('file_type', 'excel')
    
    if not semester:
        return jsonify({"message": "Semester is required"}), 400
    
    if file.filename == '':
        return jsonify({"message": "No file selected"}), 400
    
    try:
        # Store file in MongoDB GridFS
        fs = GridFS(db)
        
        # Generate unique filename
        import uuid
        file_id = str(uuid.uuid4())
        filename = f"{semester}_{file_id}_{file.filename}"
        
        # Read file content for size calculation
        file_content = file.read()
        file_size = len(file_content)
        
        # Reset file pointer
        file.seek(0)
        
        # Store file
        file_id = fs.put(file, filename=filename, semester=semester, file_type=file_type, uploaded_at=datetime.now(timezone.utc))
        
        # Store metadata in collection
        db.result_files.insert_one({
            "file_id": file_id,
            "filename": file.filename,
            "semester": semester,
            "file_type": file_type,
            "uploaded_at": datetime.now(timezone.utc),
            "file_size": file_size
        })
        
        # Recompute dashboard summary after upload
        try:
            recompute_dashboard_summary()
        except Exception as _:
            pass

        return jsonify({"message": f"File uploaded successfully for {semester.upper()}"}), 200
        
    except Exception as e:
        return jsonify({"message": f"Error uploading file: {str(e)}"}), 500

@app.route('/api/upload-gazette-file', methods=['POST', 'OPTIONS'])
@require_auth
def upload_gazette_file():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['file']
    semester = request.form.get('semester')
    
    if not semester:
        return jsonify({"message": "Semester is required"}), 400
    
    if file.filename == '':
        return jsonify({"message": "No file selected"}), 400
    
    try:
        # Store file in MongoDB GridFS
        fs = GridFS(db)
        
        # Generate unique filename
        import uuid
        file_id = str(uuid.uuid4())
        filename = f"{semester}_{file_id}_{file.filename}"
        
        # Read file content for size calculation
        file_content = file.read()
        file_size = len(file_content)
        
        # Reset file pointer
        file.seek(0)
        
        # Store file
        file_id = fs.put(file, filename=filename, semester=semester, file_type='pdf', uploaded_at=datetime.now(timezone.utc))
        
        # Store metadata in collection
        db.result_files.insert_one({
            "file_id": file_id,
            "filename": file.filename,
            "semester": semester,
            "file_type": 'pdf',
            "uploaded_at": datetime.now(timezone.utc),
            "file_size": file_size
        })
        
        # Gazette does not impact summary; skip recompute
        return jsonify({"message": f"Gazette file uploaded successfully for {semester.upper()}"}), 200
        
    except Exception as e:
        return jsonify({"message": f"Error uploading file: {str(e)}"}), 500

@app.route('/api/get-result-files', methods=['GET', 'OPTIONS'])
@require_auth
def get_result_files():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    semester = request.args.get('semester', '')
    
    try:
        query = {}
        if semester:
            query['semester'] = semester
        
        files = list(db.result_files.find(query).sort('uploaded_at', -1))
        
        # Convert ObjectId to string for JSON serialization
        for file in files:
            file['_id'] = str(file['_id'])
            file['file_id'] = str(file['file_id'])
            file['uploaded_at'] = file['uploaded_at'].isoformat()
        
        return jsonify(files), 200
        
    except Exception as e:
        return jsonify({"message": f"Error retrieving files: {str(e)}"}), 500

@app.route('/api/get-intake-files', methods=['GET', 'OPTIONS'])
@require_auth
def get_intake_files():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    try:
        files = list(db.intake_files.find().sort('uploaded_at', -1))
        
        # Convert ObjectId to string for JSON serialization
        for file in files:
            file['_id'] = str(file['_id'])
            if file.get('file_id'):
                file['file_id'] = str(file['file_id'])
            file['uploaded_at'] = file['uploaded_at'].isoformat()
        
        return jsonify(files), 200
        
    except Exception as e:
        return jsonify({"message": f"Error retrieving intake files: {str(e)}"}), 500

@app.route('/api/download-intake-file/<file_id>', methods=['GET', 'OPTIONS'])
@require_auth
def download_intake_file(file_id):
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    try:
        fs = GridFS(db)
        file_doc = db.intake_files.find_one({"_id": ObjectId(file_id)})
        if not file_doc:
            return jsonify({"message": "File not found"}), 404
        grid_id = file_doc.get('file_id')
        if not grid_id:
            return jsonify({"message": "File data not available"}), 404
        file_data = fs.get(grid_id)
        if not file_data:
            return jsonify({"message": "File data not found"}), 404
        from flask import Response
        return Response(
            file_data.read(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename="{file_doc.get("filename", "intake.xlsx")}"'}
        )
    except Exception as e:
        return jsonify({"message": f"Error downloading intake file: {str(e)}"}), 500

@app.route('/api/delete-intake-file/<file_id>', methods=['DELETE', 'OPTIONS'])
@require_auth
def delete_intake_file(file_id):
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    try:
        result = db.intake_files.delete_one({"_id": ObjectId(file_id)})
        
        if result.deleted_count == 0:
            return jsonify({"message": "Intake file not found"}), 404
        
        return jsonify({"message": "Intake file deleted successfully"}), 200
        
    except Exception as e:
        return jsonify({"message": f"Error deleting intake file: {str(e)}"}), 500

@app.route('/api/download-result-file/<file_id>', methods=['GET', 'OPTIONS'])
@require_auth
def download_result_file(file_id):
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    try:
        fs = GridFS(db)
        
        file_doc = db.result_files.find_one({"_id": ObjectId(file_id)})
        if not file_doc:
            return jsonify({"message": "File not found"}), 404
        
        gridfs_file_id = file_doc['file_id']
        file_data = fs.get(gridfs_file_id)
        if not file_data:
            return jsonify({"message": "File data not found"}), 404
        
        # Determine content type based on file extension
        filename = file_doc['filename'].lower()
        if filename.endswith('.pdf'):
            mimetype = 'application/pdf'
        elif filename.endswith('.xlsx'):
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        elif filename.endswith('.xls'):
            mimetype = 'application/vnd.ms-excel'
        else:
            mimetype = 'application/octet-stream'
        
        # Return file data for download
        from flask import Response
        return Response(
            file_data.read(),
            mimetype=mimetype,
            headers={
                'Content-Disposition': f'attachment; filename="{file_doc["filename"]}"'
            }
        )
        
    except Exception as e:
        return jsonify({"message": f"Error downloading file: {str(e)}"}), 500

@app.route('/api/delete-result-file/<file_id>', methods=['DELETE', 'OPTIONS'])
@require_auth
def delete_result_file(file_id):
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    try:
        fs = GridFS(db)
        
        # Check if file exists in metadata
        file_doc = db.result_files.find_one({"_id": ObjectId(file_id)})
        if not file_doc:
            return jsonify({"message": "File not found"}), 404
        
        # Delete from GridFS
        fs.delete(file_doc['file_id'])
        
        # Delete metadata
        db.result_files.delete_one({"_id": ObjectId(file_id)})
        
        try:
            recompute_dashboard_summary()
        except Exception:
            pass
        
        return jsonify({"message": "File deleted successfully"}), 200
        
    except Exception as e:
        return jsonify({"message": f"Error deleting file: {str(e)}"}), 500

# Serve HTML files - Block direct .html access
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/dashboard')
def dashboard():
    return app.send_static_file('dashboard.html')

@app.route('/studentprogression')
def student_progression():
    return app.send_static_file('studentprogression.html')

@app.route('/placement')
def placement():
    return app.send_static_file('placement.html')

@app.route('/extracurricular')
def extracurricular():
    return app.send_static_file('extracurricular.html')

@app.route('/reports')
def reports():
    return app.send_static_file('reports.html')

@app.route('/settings')
def settings():
    return app.send_static_file('settings.html')

@app.route('/admin')
def admin():
    return app.send_static_file('admin.html')

@app.route('/newuser')
def newuser():
    return app.send_static_file('newuser.html')

@app.route('/forgot_password')
def forgot_password():
    return app.send_static_file('forgot_password.html')

# Block all direct .html file access - redirect to 404
@app.route('/<path:filename>')
def serve_static(filename):
    # If someone tries to access .html files directly, redirect to 404
    if filename.endswith('.html'):
        return app.send_static_file('404.html'), 404
    # Allow other static files (CSS, JS, images, etc.)
    try:
        return app.send_static_file(filename)
    except:
        return app.send_static_file('404.html'), 404

# Health check endpoint for Railway
@app.route('/api/dashboard-summary-duplicate', methods=['GET', 'OPTIONS'])
@require_auth
def dashboard_summary_duplicate():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    try:
        # Get KPI data
        kpis = {}
        
        # Get sanctioned intake from intake files
        intake_files = list(db.intake_files.find())
        if intake_files:
            latest_intake = intake_files[0]  # Most recent intake file
            kpis['sanctioned_intake'] = latest_intake.get('sanctioned_intake', 0)
            kpis['total_admitted'] = latest_intake.get('total_admitted', 0)
            kpis['dse'] = latest_intake.get('dse', 0)
        
        # Get academic performance data from result files
        result_files = list(db.result_files.find())
        if result_files:
            # Calculate total students passed without backlog
            total_passed = 0
            for file in result_files:
                total_passed += file.get('without_backlog', 0)
            kpis['successfully_completed'] = total_passed
            
            # Calculate placement and higher education percentages
            kpis['placed_percentage'] = 0  # Placeholder - would need placement data
            kpis['higher_ed_percentage'] = 0  # Placeholder - would need higher ed data
        
        # Get semester data for charts
        semesters = []
        for file in result_files:
            semester_data = {
                'semester': file.get('semester', ''),
                'total': file.get('total', 0),
                'without_backlog': file.get('without_backlog', 0),
                'with_backlog': file.get('with_backlog', 0),
                'avg_cgpa': file.get('avg_cgpa', 0)
            }
            semesters.append(semester_data)
        
        return jsonify({
            'kpis': kpis,
            'semesters': semesters
        }), 200
        
    except Exception as e:
        return jsonify({"message": f"Error fetching dashboard data: {str(e)}"}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "message": "Student Progression System is running"}), 200

@app.errorhandler(404)
def page_not_found(e):
    return app.send_static_file('404.html'), 404

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'create-admin':
        create_admin_user()
    else:
        # Railway deployment configuration
        port = int(os.environ.get('PORT', 5001))
        debug_mode = os.environ.get('FLASK_ENV') != 'production'
        
        print(f"SUCCESS: Flask server is running on port {port}")
        app.run(host='0.0.0.0', port=port, debug=debug_mode)