# BusBook Travel Platform - OWASP Vulnerability Demo

🚨 **FOR EDUCATIONAL PURPOSES ONLY** 🚨

A deliberately vulnerable bus booking application demonstrating OWASP A02:2021 - Broken Authentication and other security vulnerabilities.

## 🚀 Vercel Deployment

### Prerequisites
1. [Vercel Account](https://vercel.com)
2. [Vercel CLI](https://vercel.com/cli) (optional)

### Method 1: GitHub Integration (Recommended)

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit - OWASP Vulnerability Demo"
   git branch -M main
   git remote add origin YOUR_GITHUB_REPO_URL
   git push -u origin main
   ```

2. **Deploy via Vercel Dashboard:**
   - Go to [vercel.com](https://vercel.com)
   - Click "New Project"
   - Import your GitHub repository
   - Set environment variables (see below)
   - Deploy!

### Method 2: Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy
vercel

# Set environment variables
vercel env add MONGODB_URI
vercel env add SESSION_SECRET
```

### Environment Variables (Required)

Set these in your Vercel dashboard under Project Settings > Environment Variables:

```
MONGODB_URI=mongodb+srv://123gamein:pffyW62Rqn1Kgzfa@bus.taxstpk.mongodb.net/?retryWrites=true&w=majority&appName=Bus
SESSION_SECRET=your-secret-key-here
NODE_ENV=production
```

## 🎯 Demo Features

### Available Accounts
- **Customer:** user@gmail.com / password
- **Admin:** admin@busbook.com / admin123  
- **Manager:** manager@busbook.com / manager123
- **Test User:** sarah.johnson@gmail.com / sarah123

### Vulnerability Endpoints
- `/admin` - Admin panel accessible by any user (no role validation)
- `/vulnerability` - Complete security analysis page
- `/api/admin/*` - Admin APIs accessible without proper authorization

### Key Vulnerabilities Demonstrated
1. **Broken Authentication** (OWASP A02:2021)
2. **Broken Access Control** (OWASP A01:2021)
3. **Sensitive Data Exposure** (OWASP A03:2021)
4. **Security Misconfiguration** (OWASP A05:2021)

## 🔍 Testing Instructions

1. **Login as regular user** at `/login`
2. **Access admin panel** by navigating to `/admin` (vulnerability!)
3. **View all passwords** in plain text via admin interface
4. **Exploit privilege escalation** - change user roles
5. **Extract sensitive data** via API endpoints
6. **View vulnerability analysis** at `/vulnerability`

## ⚠️ Security Notice

This application contains intentional security vulnerabilities for educational purposes:

- Plain text password storage
- No role-based access control
- Exposed sensitive data in APIs
- Weak session management
- Database credentials in source code

**NEVER deploy this to production or use for real applications!**

## 🛠️ Local Development

```bash
# Install dependencies
npm install

# Start application
npm start

# Application will be available at http://localhost:3000
```

## 📚 Educational Use

Perfect for:
- Security training
- Penetration testing practice
- OWASP Top 10 demonstrations
- Vulnerability assessment learning
- Security awareness training

## 🤝 Contributing

This is an educational project. Feel free to:
- Add more vulnerabilities
- Improve the demonstration
- Create additional test cases
- Enhance documentation

Remember: Keep it vulnerable for educational purposes!

---

**Disclaimer:** This software is for educational purposes only. The authors are not responsible for any misuse of this application.
