#!/usr/bin/env python3
"""
Railway Setup Script for Student Progression System
This script helps you prepare your project for Railway deployment
"""

import os
import json

def create_railway_config():
    """Create railway.json configuration file"""
    config = {
        "build": {
            "builder": "NIXPACKS"
        },
        "deploy": {
            "startCommand": "python app.py",
            "healthcheckPath": "/",
            "healthcheckTimeout": 100,
            "restartPolicyType": "ON_FAILURE",
            "restartPolicyMaxRetries": 10
        }
    }
    
    with open('railway.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("✅ Created railway.json")

def create_requirements():
    """Create requirements.txt file"""
    requirements = [
        "Flask==3.1.2",
        "pymongo==4.15.3", 
        "sendgrid==6.12.5",
        "flask-cors==6.0.1",
        "python-dotenv==1.0.0"
    ]
    
    with open('requirements.txt', 'w') as f:
        f.write('\n'.join(requirements))
    
    print("✅ Created requirements.txt")

def check_app_py():
    """Check if app.py has Railway configuration"""
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        checks = [
            ("os.getenv('MONGODB_URI'", "Environment variable for MongoDB"),
            ("os.getenv('SENDGRID_API_KEY'", "Environment variable for SendGrid"),
            ("host='0.0.0.0'", "Railway host configuration"),
            ("os.environ.get('PORT'", "Railway port configuration")
        ]
        
        print("\n🔍 Checking app.py configuration:")
        print("-" * 40)
        
        all_good = True
        for check, description in checks:
            if check in content:
                print(f"✅ {description}")
            else:
                print(f"❌ Missing: {description}")
                all_good = False
        
        return all_good
        
    except FileNotFoundError:
        print("❌ app.py not found")
        return False

def main():
    print("🚂 Railway Setup for Student Progression System")
    print("=" * 60)
    
    # Create configuration files
    create_railway_config()
    create_requirements()
    
    # Check app.py configuration
    app_configured = check_app_py()
    
    print("\n📋 Railway Deployment Checklist:")
    print("-" * 40)
    print("✅ railway.json created")
    print("✅ requirements.txt created")
    
    if app_configured:
        print("✅ app.py configured for Railway")
    else:
        print("❌ app.py needs Railway configuration")
        print("   Run the deployment guide to update app.py")
    
    print("\n🚀 Next Steps:")
    print("1. Push your code to GitHub")
    print("2. Connect Railway to your GitHub repo")
    print("3. Set environment variables in Railway:")
    print("   - MONGODB_URI")
    print("   - SENDGRID_API_KEY")
    print("   - FROM_EMAIL")
    print("4. Deploy!")
    
    print("\n📖 For detailed instructions, see: RAILWAY_DEPLOYMENT.md")

if __name__ == "__main__":
    main()
