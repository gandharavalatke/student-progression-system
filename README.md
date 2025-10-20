# 🎓 Student Progression System

A comprehensive web application for managing student academic records, built with Flask and MongoDB, deployed on Railway.

## 🌟 Features

- **User Authentication**: Secure login system with session management
- **Dashboard**: Real-time KPIs and file management
- **Academic Records**: Upload, view, and manage student files
- **Settings**: Profile management and password changes
- **Email Integration**: SendGrid-powered email notifications
- **Responsive Design**: Modern UI with dark/light theme support

## 🚀 Quick Start

### Local Development
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure MongoDB and SendGrid credentials in `app.py`
4. Run: `python app.py`
5. Open: `http://127.0.0.1:5001`

### Railway Deployment
See [RAILWAY_DEPLOYMENT.md](RAILWAY_DEPLOYMENT.md) for detailed deployment instructions.

## 📁 Project Structure

```
Student Progression System/
├── app.py                          # Flask backend
├── index.html                      # Login page
├── dashboard.html                  # Main dashboard
├── settings.html                   # User settings
├── studentprogression.html         # Academic records
├── newuser.html                   # User registration
├── forgot_password.html           # Password recovery
├── requirements.txt               # Python dependencies
├── railway.json                   # Railway configuration
├── RAILWAY_DEPLOYMENT.md         # Deployment guide
└── README.md                     # This file
```

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Database**: MongoDB Atlas
- **Frontend**: HTML, CSS, JavaScript, Tailwind CSS
- **Email**: SendGrid
- **Deployment**: Railway
- **File Storage**: GridFS (MongoDB)

## 🔧 Configuration

### Environment Variables
- `MONGODB_URI`: `mongodb+srv://testuser:testpassword123@sps-cluster.epkt9c1.mongodb.net/?retryWrites=true&w=majority&appName=sps-cluster&tlsAllowInvalidCertificates=true`
- `SENDGRID_API_KEY`: `SG.your-sendgrid-api-key-here`
- `FROM_EMAIL`: `gandharvacjc@gmail.com`
- `PORT`: Server port (Railway sets this automatically)

### Database Collections
- `users`: User accounts and profiles
- `authorized_faculty`: Faculty authorization list
- `student_files`: Student file uploads
- `otp_verification`: OTP verification data

## 📱 Pages Overview

### 1. Login (`index.html`)
- Secure authentication
- Theme toggle (dark/light)
- Password visibility toggle
- Error handling

### 2. Dashboard (`dashboard.html`)
- Real-time KPIs display
- File management interface
- Logout functionality
- Responsive design

### 3. Academic Records (`studentprogression.html`)
- File upload/download
- Student data management
- Search and filter functionality
- Bulk operations

### 4. Settings (`settings.html`)
- Profile management
- Password change with OTP
- Account settings
- Logout functionality

## 🔒 Security Features

- Password hashing with bcrypt
- Session management
- CORS protection
- Input validation
- Secure file uploads
- OTP verification for password changes

## 🚂 Railway Deployment

### Prerequisites
- GitHub account
- Railway account
- MongoDB Atlas account
- SendGrid account

### Quick Deploy
1. Push code to GitHub
2. Connect Railway to GitHub repo
3. Set environment variables
4. Deploy automatically

See [RAILWAY_DEPLOYMENT.md](RAILWAY_DEPLOYMENT.md) for detailed steps.

## 📊 Monitoring

- Railway provides built-in monitoring
- Real-time logs available
- Performance metrics
- Error tracking

## 🆘 Troubleshooting

### Common Issues
1. **Database Connection**: Check MongoDB URI and network access
2. **Email Not Sending**: Verify SendGrid API key and sender verification
3. **CORS Errors**: Update frontend URLs to match Railway domain
4. **Build Failures**: Check requirements.txt and Python version

### Support
- Check Railway logs for deployment issues
- Verify environment variables
- Test database connectivity
- Check email service configuration

## 📈 Performance

### Railway Free Tier
- 512MB RAM
- 1GB storage
- 100GB bandwidth/month
- Sleep after 5 minutes of inactivity

### Optimization Tips
- Use MongoDB indexes for faster queries
- Optimize file uploads
- Implement caching where appropriate
- Monitor resource usage

## 🔄 Updates and Maintenance

### Automatic Deployments
Railway automatically deploys when you push to GitHub:
1. Make changes to your code
2. Push to GitHub: `git push origin main`
3. Railway builds and deploys automatically
4. Changes go live in 2-3 minutes

### Manual Updates
1. Go to Railway dashboard
2. Click "Deploy" button
3. Select commit to deploy

## 📞 Support

- 📚 [Railway Documentation](https://docs.railway.app/)
- 💬 [Railway Discord](https://discord.gg/railway)
- 🐛 [GitHub Issues](https://github.com/your-repo/issues)

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- Flask community for the excellent framework
- MongoDB for the database solution
- Railway for the deployment platform
- SendGrid for email services
- Tailwind CSS for the beautiful UI

---

**Built with ❤️ for educational institutions**
