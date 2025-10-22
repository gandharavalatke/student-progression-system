#!/usr/bin/env python3
"""
Script to update frontend URLs from localhost to Railway production URL
Run this script after getting your Railway deployment URL
"""

import os
import re

def update_file_urls(file_path, old_url, new_url):
    """Update URLs in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Replace the old URL with new URL
        updated_content = content.replace(old_url, new_url)
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(updated_content)
        
        print(f"✅ Updated {file_path}")
        return True
    except Exception as e:
        print(f"❌ Error updating {file_path}: {e}")
        return False

def main():
    print("🚀 Railway URL Update Script")
    print("=" * 50)
    
    # Get Railway URL from user
    railway_url = input("Enter your Railway app URL (e.g., https://your-app-name.railway.app): ").strip()
    
    if not railway_url:
        print("❌ No URL provided. Exiting.")
        return
    
    if not railway_url.startswith('http'):
        railway_url = f"https://{railway_url}"
    
    # Local development URL
    local_url = "http://127.0.0.1:5001"
    
    # Files to update
    html_files = [
        'index.html',
        'dashboard.html', 
        'settings.html',
        'studentprogression.html',
        'newuser.html',
        'forgot_password.html'
    ]
    
    print(f"\n🔄 Updating URLs from {local_url} to {railway_url}")
    print("-" * 50)
    
    success_count = 0
    for file_path in html_files:
        if os.path.exists(file_path):
            if update_file_urls(file_path, local_url, railway_url):
                success_count += 1
        else:
            print(f"⚠️  File not found: {file_path}")
    
    print(f"\n✅ Successfully updated {success_count}/{len(html_files)} files")
    print(f"🌐 Your app is now configured for Railway: {railway_url}")
    print("\n📝 Next steps:")
    print("1. Commit and push your changes to GitHub")
    print("2. Railway will automatically redeploy")
    print("3. Test your deployed application")

if __name__ == "__main__":
    main()
