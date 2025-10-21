import os
import sys
from flask import Flask, request, jsonify, session, redirect
from flask_cors import CORS

# --- Flask App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-here')

# CORS configuration
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Add global CORS headers for all routes
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# --- Health Check Endpoints ---
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "Student Progression System is running"}), 200

# --- Serve Static HTML Files ---
@app.route('/', methods=['GET'])
def serve_index():
    return app.send_static_file('index.html')

@app.route('/dashboard', methods=['GET'])
def serve_dashboard():
    return app.send_static_file('dashboard.html')

@app.route('/dashboard.html', methods=['GET'])
def serve_dashboard_html():
    return app.send_static_file('dashboard.html')

@app.route('/studentprogression', methods=['GET'])
def serve_studentprogression():
    return app.send_static_file('studentprogression.html')

@app.route('/studentprogression.html', methods=['GET'])
def serve_studentprogression_html():
    return app.send_static_file('studentprogression.html')

@app.route('/placement', methods=['GET'])
def serve_placement():
    return app.send_static_file('placement.html')

@app.route('/placement.html', methods=['GET'])
def serve_placement_html():
    return app.send_static_file('placement.html')

@app.route('/extracurricular', methods=['GET'])
def serve_extracurricular():
    return app.send_static_file('extracurricular.html')

@app.route('/extracurricular.html', methods=['GET'])
def serve_extracurricular_html():
    return app.send_static_file('extracurricular.html')

@app.route('/reports', methods=['GET'])
def serve_reports():
    return app.send_static_file('reports.html')

@app.route('/reports.html', methods=['GET'])
def serve_reports_html():
    return app.send_static_file('reports.html')

@app.route('/settings', methods=['GET'])
def serve_settings():
    return app.send_static_file('settings.html')

@app.route('/settings.html', methods=['GET'])
def serve_settings_html():
    return app.send_static_file('settings.html')

@app.route('/newuser', methods=['GET'])
def serve_newuser():
    return app.send_static_file('newuser.html')

@app.route('/forgot_password', methods=['GET'])
def serve_forgot_password():
    return app.send_static_file('forgot_password.html')

@app.route('/admin', methods=['GET'])
def serve_admin():
    return app.send_static_file('admin.html')

# --- Batch Filtering API ---
@app.route('/api/available-batches', methods=['GET'])
def get_available_batches():
    """Get list of available batches for filtering."""
    try:
        # Return default batches for now
        batches = ["2024-25", "2023-24", "2022-23", "2021-22"]
        return jsonify({"batches": batches}), 200
    except Exception as e:
        return jsonify({"message": f"Error getting batches: {e}"}), 500

@app.route('/api/dashboard-summary', methods=['GET'])
def get_dashboard_summary():
    """Get dashboard summary with batch filtering"""
    try:
        batch_filter = request.args.get('batch', '2024-25')
        
        # Mock data for demonstration
        mock_data = {
            "current_batch": batch_filter,
            "updated_at": "2024-01-01T00:00:00Z",
            "semesters": [
                {"semester": "sem1", "total": 120, "without_backlog": 100, "with_backlog": 20, "left": 0, "avg_cgpa": 8.5},
                {"semester": "sem2", "total": 120, "without_backlog": 95, "with_backlog": 25, "left": 0, "avg_cgpa": 8.2},
                {"semester": "sem3", "total": 120, "without_backlog": 90, "with_backlog": 30, "left": 0, "avg_cgpa": 8.0},
                {"semester": "sem4", "total": 120, "without_backlog": 85, "with_backlog": 35, "left": 0, "avg_cgpa": 7.8}
            ],
            "kpis": {
                "sanctioned_intake": 120,
                "total_admitted": 120,
                "dse": 5,
                "successfully_completed": 85,
                "placed_percentage": 75,
                "higher_ed_percentage": 15
            }
        }
        
        return jsonify(mock_data), 200
    except Exception as e:
        return jsonify({"message": f"Error getting dashboard data: {e}"}), 500

# --- Authentication API (Simplified) ---
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login_user():
    if request.method == 'OPTIONS':
        return jsonify(status='ok'), 200
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Simple authentication for demo
    if username == 'admin' and password == 'admin123':
        session['user_id'] = 'demo_user'
        session['username'] = username
        return jsonify({"message": "Login successful!"}), 200
    
    return jsonify({"message": "Invalid username or password"}), 401

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' not in session:
        return jsonify({"authenticated": False}), 401
    
    return jsonify({"authenticated": True, "username": session.get('username')}), 200

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect('/', code=302)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    print(f"Flask server starting on port {port}")
    print(f"Health check: http://localhost:{port}/api/health")
    print(f"Main app: http://localhost:{port}/")
    print(f"Demo login: admin / admin123")
    
    try:
        app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)
    except Exception as e:
        print(f"Failed to start Flask server: {e}")
        sys.exit(1)
