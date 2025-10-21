#!/usr/bin/env python3
"""
Script to fix navigation issues in all HTML files
"""

import os
import re

def fix_navigation_links(file_path):
    """Fix hardcoded navigation links in HTML files"""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix desktop navigation links
    content = re.sub(
        r'href="/[a-z]+-[a-z0-9]+"',
        'href="#"',
        content
    )
    
    # Add IDs to navigation links
    content = re.sub(
        r'<a href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\s*<i class="fa-solid fa-chart-pie',
        '<a id="nav-dashboard" href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\n                    <i class="fa-solid fa-chart-pie',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="flex items-center p-3 text-white bg-blue-600/20 rounded-lg transition-colors border border-blue-500/30">\s*<i class="fa-solid fa-arrow-trend-up',
        '<a id="nav-academic" href="#" class="flex items-center p-3 text-white bg-blue-600/20 rounded-lg transition-colors border border-blue-500/30">\n                    <i class="fa-solid fa-arrow-trend-up',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\s*<i class="fa-solid fa-graduation-cap',
        '<a id="nav-placement" href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\n                    <i class="fa-solid fa-graduation-cap',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\s*<i class="fa-solid fa-trophy',
        '<a id="nav-extracurricular" href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\n                    <i class="fa-solid fa-trophy',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\s*<i class="fa-solid fa-file-alt',
        '<a id="nav-reports" href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\n                    <i class="fa-solid fa-file-alt',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\s*<i class="fa-solid fa-cog',
        '<a id="nav-settings" href="#" class="flex items-center p-3 text-slate-300 hover:bg-slate-700/50 rounded-lg transition-colors hover:text-white">\n                    <i class="fa-solid fa-cog',
        content
    )
    
    # Fix mobile navigation links
    content = re.sub(
        r'<a href="#" class="mobile-nav-item">\s*<i class="fa-solid fa-chart-pie',
        '<a id="mobile-nav-dashboard" href="#" class="mobile-nav-item">\n                    <i class="fa-solid fa-chart-pie',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="mobile-nav-item">\s*<i class="fa-solid fa-arrow-trend-up',
        '<a id="mobile-nav-academic" href="#" class="mobile-nav-item">\n                    <i class="fa-solid fa-arrow-trend-up',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="mobile-nav-item">\s*<i class="fa-solid fa-graduation-cap',
        '<a id="mobile-nav-placement" href="#" class="mobile-nav-item">\n                    <i class="fa-solid fa-graduation-cap',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="mobile-nav-item">\s*<i class="fa-solid fa-trophy',
        '<a id="mobile-nav-extracurricular" href="#" class="mobile-nav-item">\n                    <i class="fa-solid fa-trophy',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="mobile-nav-item">\s*<i class="fa-solid fa-file-alt',
        '<a id="mobile-nav-reports" href="#" class="mobile-nav-item">\n                    <i class="fa-solid fa-file-alt',
        content
    )
    
    content = re.sub(
        r'<a href="#" class="mobile-nav-item">\s*<i class="fa-solid fa-cog',
        '<a id="mobile-nav-settings" href="#" class="mobile-nav-item">\n                    <i class="fa-solid fa-cog',
        content
    )
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed navigation links in {file_path}")

def main():
    """Main function to fix all HTML files"""
    
    html_files = [
        'dashboard.html',
        'studentprogression.html', 
        'placement.html',
        'extracurricular.html',
        'reports.html',
        'settings.html'
    ]
    
    for file_path in html_files:
        if os.path.exists(file_path):
            fix_navigation_links(file_path)
        else:
            print(f"File {file_path} not found")

if __name__ == "__main__":
    main()
