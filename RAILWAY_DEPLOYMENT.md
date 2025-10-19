# 🚀 Railway Deployment Guide - Student Progression System

This guide will help you deploy your Student Progression System to Railway, a modern cloud platform that makes deployment simple and fast.

## 📋 Prerequisites

Before starting, ensure you have:
- ✅ A GitHub account
- ✅ A Railway account (free tier available)
- ✅ Your project code pushed to GitHub
- ✅ MongoDB Atlas account (already configured)
- ✅ SendGrid account (already configured)

## 🗄️ Database Setup (MongoDB Atlas)

### Step 1: MongoDB Atlas Configuration
Your MongoDB Atlas is already configured with:
- **Cluster**: `sps-cluster.epkt9c1.mongodb.net`
- **Database**: `StudentProgressionDB`
- **Username**: `testuser`
- **Password**: `testpassword123`
- **Connection String**: `mongodb+srv://testuser:testpassword123@sps-cluster.epkt9c1.mongodb.net/?retryWrites=true&w=majority&appName=sps-cluster&tlsAllowInvalidCertificates=true`

**Note**: Your MongoDB Atlas is already set up and ready for Railway deployment!

### Step 2: Create Database Collections
Your app will automatically create these collections:
- `users` - User accounts
- `authorized_faculty` - Faculty authorization list
- `student_files` - Student file uploads
- `otp_verification` - OTP verification data

## 📧 Email Service Setup (SendGrid)

### Step 1: SendGrid Configuration
Your SendGrid is already configured with:
- **API Key**: `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`
- **From Email**: `gandharvacjc@gmail.com`
- **From Name**: `SPS Admin - GIT`

**Note**: Your SendGrid is already set up and ready for Railway deployment!

## 🚂 Railway Deployment

### Step 1: Prepare Your Project

#### 1.1 Create requirements.txt
Create a `requirements.txt` file in your project root:

```txt
Flask==3.1.2
pymongo==4.15.3
sendgrid==6.12.5
flask-cors==6.0.1
python-dotenv==1.0.0
```

#### 1.2 Create railway.json
Create a `railway.json` file in your project root:

```json
{
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
```

#### 1.3 Update app.py for Production
Add these lines at the top of your `app.py` file (after imports):

```python
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Update your MongoDB connection
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://username:password@cluster.mongodb.net/')
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', 'your-sendgrid-api-key')

# Update your client initialization
client = MongoClient(MONGODB_URI)
```

### Step 2: Deploy to Railway

#### 2.1 Connect to Railway
1. Go to [Railway](https://railway.app/)
2. Sign up with your GitHub account
3. Click "New Project"
4. Select "Deploy from GitHub repo"
5. Choose your repository
6. Railway will automatically detect it's a Python project

#### 2.2 Configure Environment Variables
In your Railway project dashboard:

1. Go to the "Variables" tab
2. Add these environment variables:

```
MONGODB_URI=mongodb+srv://testuser:testpassword123@sps-cluster.epkt9c1.mongodb.net/?retryWrites=true&w=majority&appName=sps-cluster&tlsAllowInvalidCertificates=true
SENDGRID_API_KEY=SG.your-sendgrid-api-key-here
FROM_EMAIL=gandharvacjc@gmail.com
FLASK_ENV=production
PORT=5000
```

#### 2.3 Deploy
1. Railway will automatically start building and deploying
2. Wait for the deployment to complete (usually 2-3 minutes)
3. Your app will be available at a Railway-provided URL

## 🔧 Configuration Steps

### Step 1: Update Frontend URLs
Update all your HTML files to use the Railway URL instead of localhost:

**In all HTML files, replace:**
```javascript
// OLD - Local development
const API_BASE = 'http://127.0.0.1:5001';

// NEW - Railway production
const API_BASE = 'https://your-app-name.railway.app';
```

**Files to update:**
- `index.html`
- `dashboard.html`
- `settings.html`
- `studentprogression.html`
- `newuser.html`
- `forgot_password.html`

### Step 2: Update Flask App Configuration
In your `app.py`, update the CORS and host settings:

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=['https://your-app-name.railway.app', 'https://your-frontend-domain.com'])

# Update the port configuration
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
```

## 🌐 Custom Domain (Optional)

### Step 1: Add Custom Domain
1. In Railway dashboard, go to "Settings"
2. Click "Domains"
3. Add your custom domain
4. Update DNS records as instructed

### Step 2: Update CORS Settings
Update your `app.py` CORS configuration:

```python
CORS(app, origins=[
    'https://your-custom-domain.com',
    'https://your-app-name.railway.app'
])
```

## 📊 Monitoring and Logs

### View Logs
1. Go to your Railway project dashboard
2. Click on "Deployments"
3. Click on your latest deployment
4. View real-time logs

### Monitor Performance
- Railway provides built-in metrics
- Check CPU, memory, and network usage
- Set up alerts for downtime

## 🔒 Security Best Practices

### Environment Variables
- ✅ Never commit API keys to GitHub
- ✅ Use Railway's environment variables
- ✅ Rotate keys regularly

### Database Security
- ✅ Use strong passwords
- ✅ Enable IP whitelisting
- ✅ Regular backups

### Application Security
- ✅ Use HTTPS (Railway provides this automatically)
- ✅ Validate all inputs
- ✅ Implement rate limiting

## 🚨 Troubleshooting

### Common Issues

#### 1. Build Failures
**Problem**: Build fails during deployment
**Solution**: 
- Check `requirements.txt` has all dependencies
- Ensure Python version compatibility
- Check build logs in Railway dashboard

#### 2. Database Connection Issues
**Problem**: Cannot connect to MongoDB
**Solution**:
- Verify `MONGODB_URI` is correct
- Check MongoDB Atlas IP whitelist
- Ensure database user has proper permissions

#### 3. Email Not Sending
**Problem**: SendGrid emails not working
**Solution**:
- Verify `SENDGRID_API_KEY` is correct
- Check SendGrid sender verification
- Review SendGrid activity logs

#### 4. CORS Errors
**Problem**: Frontend can't connect to backend
**Solution**:
- Update CORS origins in `app.py`
- Ensure URLs match exactly
- Check HTTPS/HTTP protocol mismatch

### Debug Commands

```bash
# Check Railway logs
railway logs

# Connect to Railway shell
railway shell

# Check environment variables
railway variables
```

## 📈 Scaling and Performance

### Railway Free Tier Limits
- 512MB RAM
- 1GB storage
- 100GB bandwidth/month
- Sleep after 5 minutes of inactivity

### Upgrade Options
- **Hobby Plan**: $5/month - No sleep, more resources
- **Pro Plan**: $20/month - Production features
- **Team Plan**: $99/month - Team collaboration

## 🔄 Continuous Deployment

### Automatic Deployments
Railway automatically deploys when you push to your main branch:

1. Make changes to your code
2. Push to GitHub: `git push origin main`
3. Railway automatically builds and deploys
4. Your changes go live in 2-3 minutes

### Manual Deployments
1. Go to Railway dashboard
2. Click "Deploy" button
3. Select the commit to deploy

## 📞 Support and Resources

### Railway Support
- 📚 [Railway Documentation](https://docs.railway.app/)
- 💬 [Railway Discord](https://discord.gg/railway)
- 🐛 [Railway GitHub](https://github.com/railwayapp)

### Your Project Support
- 📧 Contact: [Your Email]
- 🐛 Issues: [Your GitHub Issues]
- 📖 Documentation: [Your Project README]

## ✅ Deployment Checklist

Before going live, ensure:

- [ ] All environment variables set
- [ ] Database connection working
- [ ] Email service configured
- [ ] Frontend URLs updated
- [ ] CORS properly configured
- [ ] HTTPS enabled (automatic with Railway)
- [ ] Error handling implemented
- [ ] Logging configured
- [ ] Backup strategy in place

## 🎉 Congratulations!

Your Student Progression System is now live on Railway! 

**Your app URL**: `https://your-app-name.railway.app`

**Next Steps**:
1. Test all functionality
2. Set up monitoring
3. Configure backups
4. Plan for scaling

---

**Need Help?** Check the troubleshooting section or contact support! 🚀
