#!/usr/bin/env python3
"""
Minimal version of the main Flask app for Railway deployment
"""
import os
from flask import Flask, request, jsonify, session, redirect, send_from_directory

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback-secret-key')

# --- Health Check Endpoints ---
@app.route('/')
def root_health_check():
    """Root health check for Railway deployment"""
    return "OK", 200

@app.route('/health', methods=['GET'])
def simple_health_check():
    """Simple health check for Railway deployment"""
    return "OK", 200

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "Student Progression System is running"}), 200

@app.route('/test', methods=['GET'])
def test_route():
    """Test route for debugging"""
    return "Flask app is working!", 200

# --- Direct routes for HTML pages ---
@app.route('/newuser.html', methods=['GET'])
def serve_newuser():
    return send_from_directory('.', 'newuser.html')

@app.route('/forgot_password.html', methods=['GET'])
def serve_forgot_password():
    return send_from_directory('.', 'forgot_password.html')

@app.route('/admin.html', methods=['GET'])
def serve_admin():
    return send_from_directory('.', 'admin.html')

@app.route('/dashboard.html', methods=['GET'])
def serve_dashboard():
    if 'user_id' not in session:
        return redirect('/')
    return send_from_directory('.', 'dashboard.html')

@app.route('/studentprogression.html', methods=['GET'])
def serve_studentprogression():
    if 'user_id' not in session:
        return redirect('/')
    return send_from_directory('.', 'studentprogression.html')

@app.route('/settings.html', methods=['GET'])
def serve_settings():
    if 'user_id' not in session:
        return redirect('/')
    return send_from_directory('.', 'settings.html')

@app.route('/placement.html', methods=['GET'])
def serve_placement():
    if 'user_id' not in session:
        return redirect('/')
    return send_from_directory('.', 'placement.html')

@app.route('/extracurricular.html', methods=['GET'])
def serve_extracurricular():
    if 'user_id' not in session:
        return redirect('/')
    return send_from_directory('.', 'extracurricular.html')

@app.route('/reports.html', methods=['GET'])
def serve_reports():
    if 'user_id' not in session:
        return redirect('/')
    return send_from_directory('.', 'reports.html')

# --- Serve index.html at root ---
@app.route('/index.html', methods=['GET'])
def serve_index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    try:
        print("=" * 60)
        print("MINIMAL STUDENT PROGRESSION SYSTEM - STARTING")
        print("=" * 60)
        
        port = int(os.environ.get('PORT', 5001))
        debug_mode = os.environ.get('FLASK_ENV') != 'production'
        
        print(f"✓ Flask app initialized successfully")
        print(f"✓ Port: {port}")
        print(f"✓ Debug mode: {debug_mode}")
        print(f"✓ Health check: http://0.0.0.0:{port}/")
        print(f"✓ API health: http://0.0.0.0:{port}/api/health")
        
        print("=" * 60)
        print("STARTING FLASK SERVER...")
        print("=" * 60)
        
        app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)
        
    except Exception as e:
        print("=" * 60)
        print("CRITICAL ERROR - FLASK SERVER FAILED TO START")
        print("=" * 60)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        print("=" * 60)
        import sys
        sys.exit(1)
