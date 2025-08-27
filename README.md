# OWASP Broken Authentication Demo

A professional, interactive demonstration of OWASP A02:2021 - Broken Authentication vulnerabilities with comprehensive fixes and security best practices.

## 🎯 Purpose

This application serves as an educational tool for security researchers, developers, and penetration testers to understand:

- Common authentication vulnerabilities
- Attack vectors and exploitation techniques
- Proper security implementations and fixes
- Real-world impact of broken authentication

## 🚨 IMPORTANT DISCLAIMER

**FOR EDUCATIONAL PURPOSES ONLY**

This application intentionally contains security vulnerabilities. It should NEVER be deployed in a production environment or accessible over the internet. Use only in controlled, isolated environments for learning and demonstration purposes.

## 🏗️ Architecture

### Technology Stack
- **Backend**: Node.js with Express.js
- **Frontend**: Vanilla HTML5, CSS3, JavaScript
- **Security**: bcrypt, helmet, express-rate-limit
- **Session Management**: express-session

### Application Structure
```
owasp-broken-authentication-demo/
├── server.js              # Main server with vulnerable & secure endpoints
├── package.json           # Dependencies and scripts
├── README.md              # This file
└── public/
    ├── index.html         # Professional UI interface
    ├── styles.css         # Modern responsive styling
    └── script.js          # Interactive functionality
```

## 🔧 Setup Instructions

### Prerequisites
- Node.js 16+ installed
- npm package manager

### Installation

1. **Clone or download the project**
   ```bash
   cd /path/to/OWASP_VUL
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the application**
   ```bash
   npm start
   ```
   
   For development with auto-reload:
   ```bash
   npm run dev
   ```

4. **Access the application**
   Open your browser and navigate to: `http://localhost:3000`

## 🎮 Demo Credentials

### Vulnerable Login
- **Username**: `admin` | **Password**: `admin123`
- **Username**: `user` | **Password**: `password`

### Secure Login
- **Username**: `admin` | **Password**: `SecurePass123!`
- **Username**: `user` | **Password**: `SecurePass123!`

## 🐛 Demonstrated Vulnerabilities

### 1. **Plain Text Password Storage** (Critical)
- **Issue**: Passwords stored without encryption
- **Impact**: Complete credential compromise if database is breached
- **Location**: `users` array in server.js

### 2. **Weak Session Management** (High)
- **Issue**: Insecure session configuration
- **Impact**: Session hijacking, XSS attacks
- **Details**: 
  - `httpOnly: false` - Accessible via JavaScript
  - `secure: false` - Transmitted over HTTP
  - Predictable session IDs

### 3. **No Rate Limiting** (High)
- **Issue**: Unlimited login attempts allowed
- **Impact**: Brute force attacks, credential stuffing
- **Demonstration**: Automated password guessing

### 4. **Information Disclosure** (Medium)
- **Issue**: Detailed error messages reveal system information
- **Impact**: Username enumeration, system reconnaissance
- **Example**: "Username not found" vs "Invalid password"

### 5. **No Account Lockout** (High)
- **Issue**: Accounts never locked after failed attempts
- **Impact**: Persistent brute force attacks
- **Risk**: Credential stuffing campaigns

### 6. **Insecure Password Reset** (Critical)
- **Issue**: Password reset without authentication
- **Impact**: Account takeover
- **Details**: No email verification or identity confirmation

## 🛡️ Security Fixes Implemented

### 1. **Strong Password Policies**
```javascript
const passwordPolicy = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true
};
```

### 2. **Secure Password Storage**
```javascript
// bcrypt with salt rounds of 12
const hashedPassword = await bcrypt.hash(password, 12);
```

### 3. **Secure Session Configuration**
```javascript
{
    secret: process.env.SESSION_SECRET,
    cookie: {
        secure: true,      // HTTPS only
        httpOnly: true,    // No JavaScript access
        maxAge: 1800000,   // 30 minutes
        sameSite: 'strict' // CSRF protection
    }
}
```

### 4. **Rate Limiting & Account Lockout**
```javascript
// 5 attempts per 15 minutes
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5
});
```

### 5. **Input Validation**
```javascript
body('username').isLength({ min: 3, max: 30 }).trim().escape(),
body('password').isLength({ min: 8, max: 128 })
```

### 6. **Session Regeneration**
```javascript
req.session.regenerate((err) => {
    // New session ID after successful login
});
```

## 🔍 Attack Demonstrations

### 1. **Brute Force Attack**
- Automated password guessing
- Common password dictionary
- No protection against repeated attempts

### 2. **Session Hijacking**
- Cookie inspection and manipulation
- XSS vulnerability demonstration
- Session fixation attacks

### 3. **Password Reset Exploitation**
- Unauthorized password changes
- No identity verification bypass
- Account takeover scenarios

## 📊 Security Monitoring

The secure implementation includes:

- **Login attempt tracking**
- **Failed authentication logging**
- **Rate limit monitoring**
- **Session security events**
- **Attack prevention alerts**

## 🎯 Learning Objectives

After using this demo, you should understand:

1. **Common authentication vulnerabilities** and their exploitation
2. **Impact assessment** of broken authentication
3. **Proper security implementations** and best practices
4. **Defense mechanisms** against authentication attacks
5. **Security monitoring** and incident response

## 🧪 Testing Scenarios

### Vulnerability Testing
1. Test weak password acceptance
2. Attempt brute force attacks
3. Analyze session cookies
4. Test password reset functionality
5. Examine error message disclosure

### Security Testing
1. Verify rate limiting effectiveness
2. Test account lockout mechanisms
3. Validate session security
4. Confirm input validation
5. Check audit logging

## 📚 Additional Resources

### OWASP References
- [OWASP Top 10 - A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

### Security Standards
- NIST Cybersecurity Framework
- ISO 27001 Authentication Controls
- PCI DSS Authentication Requirements

## 🤝 Contributing

This is an educational project. Contributions for:
- Additional vulnerability scenarios
- Enhanced security demonstrations
- Improved documentation
- Better UI/UX

## ⚖️ License

MIT License - Educational and demonstration purposes only.

## 🔐 Security Notice

This application contains intentional vulnerabilities and should:
- ❌ Never be deployed to production
- ❌ Never be accessible over the internet
- ❌ Never contain real user data
- ✅ Only be used in isolated environments
- ✅ Be used for educational purposes only
- ✅ Be properly secured and monitored when testing

## 📞 Support

For questions about security implementations or educational use of this demo, please refer to the OWASP community resources and security documentation.

---

**Remember**: The goal is to learn and improve security practices. Always implement proper security measures in real applications!
