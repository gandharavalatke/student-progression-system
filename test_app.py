#!/usr/bin/env python3
"""
Minimal Flask app for testing Railway deployment
"""
import os
from flask import Flask

app = Flask(__name__)

@app.route('/')
def health_check():
    return "OK", 200

@app.route('/health')
def health():
    return "OK", 200

@app.route('/api/health')
def api_health():
    return {"status": "healthy"}, 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    print(f"Starting minimal Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
