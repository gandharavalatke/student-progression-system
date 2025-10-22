@echo off
echo 🚀 Uploading Student Progression System to GitHub
echo ================================================

echo.
echo Adding project files to Git...

git add .gitignore
git add app.py
git add *.html
git add *.json
git add *.md
git add *.txt
git add *.py
git add *.bat

echo.
echo Committing changes...
git commit -m "Initial commit: Student Progression System with Railway deployment configuration"

echo.
echo Pushing to GitHub...
git push -u origin main

echo.
echo ✅ Upload complete! Your project is now on GitHub.
echo 🌐 Repository: https://github.com/gandharavalatke/student-progression-system
echo.
echo 🚂 Next steps for Railway deployment:
echo 1. Go to https://railway.app/
echo 2. Connect your GitHub repository
echo 3. Add environment variables (see RAILWAY_CREDENTIALS.md)
echo 4. Deploy!

pause
