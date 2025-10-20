import bcrypt
import os
import certifi
import pandas as pd
import random
import secrets
import string
import sys
import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient
from gridfs import GridFS
from bson import ObjectId
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from io import BytesIO
# --- Flask App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# A more robust CORS configuration
# Ensure TLS verification uses an up-to-date CA bundle (fixes SSL errors on some Windows setups)
os.environ.setdefault('SSL_CERT_FILE', certifi.where())
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Add global CORS headers for all routes
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response 

# --- CRITICAL CONFIGURATION ---
# Use environment variables for Railway deployment, fallback to local values
MONGO_URI = os.getenv('MONGODB_URI', "mongodb+srv://testuser:testpassword123@sps-cluster.epkt9c1.mongodb.net/?retryWrites=true&w=majority&appName=sps-cluster&tlsAllowInvalidCertificates=true")
DB_NAME = "StudentProgressionDB" 
# --- ACTION REQUIRED: PASTE YOUR NEW, VALID SENDGRID API KEY HERE ---
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', 'SG.your-sendgrid-api-key-here')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'gandharvacjc@gmail.com') # This MUST be a "Verified Sender" in your SendGrid account
FROM_NAME = 'SPS Admin - GIT'

# --- DYNAMIC ID GENERATION SYSTEM ---
def generate_dynamic_id(page_type):
    """Generate a unique, time-based ID for each page access"""
    timestamp = str(int(time.time() * 1000))  # milliseconds
    random_part = secrets.token_hex(8)
    page_hash = hashlib.md5(page_type.encode()).hexdigest()[:8]
    return f"{page_type}-{timestamp}-{random_part}-{page_hash}"

def get_or_create_page_id(page_type):
    """Get existing page ID from session or create new one"""
    session_key = f"{page_type}_id"
    if session_key not in session:
        session[session_key] = generate_dynamic_id(page_type)
    return session[session_key]

# Page type mappings
PAGE_TYPES = {
    'dashboard': 'dash',
    'settings': 'settings', 
    'academic': 'academic',
    'newuser': 'newuser',
    'forgot': 'forgot',
    'admin': 'admin'
}

# --- Health Check Endpoints for Railway ---
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "Student Progression System is running"}), 200

# --- Dynamic ID Generation API ---
@app.route('/api/generate-id/<page_type>', methods=['GET'])
def generate_page_id(page_type):
    """Generate a new dynamic ID for a specific page type"""
    if page_type not in PAGE_TYPES:
        return jsonify({"error": "Invalid page type"}), 400
    
    # Generate new ID for this session
    new_id = generate_dynamic_id(PAGE_TYPES[page_type])
    session[f"{page_type}_id"] = new_id
    
    return jsonify({
        "id": new_id,
        "page_type": page_type,
        "url": f"/{new_id}"
    }), 200

@app.route('/api/get-current-ids', methods=['GET'])
def get_current_ids():
    """Get all current page IDs for this session"""
    current_ids = {}
    for page_type in PAGE_TYPES:
        session_key = f"{page_type}_id"
        if session_key in session:
            current_ids[page_type] = session[session_key]
        else:
            # Generate new ID if not exists
            new_id = generate_dynamic_id(PAGE_TYPES[page_type])
            session[session_key] = new_id
            current_ids[page_type] = new_id
    
    return jsonify(current_ids), 200

# --- Serve Static HTML Files ---
@app.route('/', methods=['GET'])
def serve_index():
    return app.send_static_file('index.html')

@app.route('/<dynamic_id>', methods=['GET'])
def serve_dynamic_page(dynamic_id):
    """Serve pages with dynamic IDs - validates ID format and serves appropriate page"""
    try:
        # Extract page type from dynamic ID
        if dynamic_id.startswith('dash-'):
            return app.send_static_file('dashboard.html')
        elif dynamic_id.startswith('settings-'):
            return app.send_static_file('settings.html')
        elif dynamic_id.startswith('academic-'):
            return app.send_static_file('studentprogression.html')
        elif dynamic_id.startswith('newuser-'):
            return app.send_static_file('newuser.html')
        elif dynamic_id.startswith('forgot-'):
            return app.send_static_file('forgot_password.html')
        elif dynamic_id.startswith('admin-'):
            return app.send_static_file('admin.html')
        else:
            return "Page not found", 404
    except Exception as e:
        return f"Error serving page: {str(e)}", 500

@app.route('/newuser', methods=['GET'])
def serve_newuser():
    return app.send_static_file('newuser.html')

@app.route('/forgot-password', methods=['GET'])
def serve_forgot_password():
    return app.send_static_file('forgot_password.html')

@app.route('/admin', methods=['GET'])
def serve_admin():
    return app.send_static_file('admin.html')

@app.route('/gitlogosite.jpg', methods=['GET'])
def serve_logo():
    return app.send_static_file('gitlogosite.jpg')

# --- Initial Health Check ---
if 'PASTE_YOUR' in SENDGRID_API_KEY:
    print("CRITICAL ERROR: The SendGrid API key is still a placeholder. Update it in app.py before running.")
    sys.exit(1)

# --- Database Connection ---
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    client.admin.command('ismaster')
    print("SUCCESS: Successfully connected to MongoDB Atlas!")
except Exception as e:
    print(f"WARNING: DATABASE CONNECTION ISSUE: {e}")
    print("Continuing without database connection for health check...")
    # Don't exit - let the app start for health check

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

# --- API Endpoints ---

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    admin_doc = db.users.find_one({"username": "admin", "role": "admin"})
    if admin_doc and bcrypt.checkpw(data.get('password').encode('utf-8'), admin_doc['password']):
        return jsonify({"message": "Admin authentication successful!"}), 200
    return jsonify({"message": "Invalid admin credentials"}), 401

@app.route('/api/upload-faculty', methods=['POST'])
def upload_faculty_list():
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
def login_user():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    data = request.get_json()
    user = db.users.find_one({"username": data.get('username')})
    if user and 'password' in user and bcrypt.checkpw(data.get('password').encode('utf-8'), user['password']):
        return jsonify({"message": "Login successful!"}), 200
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


@app.route('/api/dashboard-summary', methods=['GET'])
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


@app.route('/api/export-result-summary', methods=['GET'])
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

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'create-admin':
        create_admin_user()
    else:
        # Railway deployment configuration
        port = int(os.environ.get('PORT', 5001))
        debug_mode = os.environ.get('FLASK_ENV') != 'production'
        
        print(f"SUCCESS: Flask server is running on port {port}")
        print(f"Health check endpoint: http://0.0.0.0:{port}/")
        print(f"API health check: http://0.0.0.0:{port}/api/health")
        
        try:
            app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)
        except Exception as e:
            print(f"ERROR: Failed to start Flask server: {e}")
            sys.exit(1)