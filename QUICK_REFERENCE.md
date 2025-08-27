# OWASP A02:2021 - Quick Demo Reference

## 🎯 Enhanced Demo Features

### New User Roles
- **👤 Normal User**: `user / password` (Role: user)
- **👨‍💼 Admin User**: `admin / admin123` (Role: admin)  
- **🔑 Root User**: `root / root` (Role: root)

### Critical Vulnerabilities Added

#### 1. **Privilege Escalation**
- Normal users can access admin/root dashboards
- Missing role-based access control validation
- **Impact**: Complete system compromise

#### 2. **Sensitive Data Exposure**
- Root access exposes all user passwords
- Database credentials leaked
- AWS credentials exposed
- Employee SSNs and salary data revealed

## 🚨 Live Demonstration Steps

### Step 1: Login as Normal User
1. Go to "Vulnerable Demo" tab
2. Login with: `user / password`
3. Note the user role in the response

### Step 2: Demonstrate Privilege Escalation
1. Click "Privilege Escalation" button
2. Click "Access Admin Dashboard" button
3. Click "Access Root Dashboard" button
4. Observe the critical data exposure

### Step 3: Show Vulnerable Code
The vulnerabilities exist in these server.js locations:

#### Admin Endpoint (Line ~180)
```javascript
app.get('/api/dashboard/admin/vulnerable', (req, res) => {
    // VULNERABILITY: No role validation!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    // Missing: role check for admin access
    res.json({ adminData: {...} }); // Exposes sensitive data
});
```

#### Root Endpoint (Line ~200)  
```javascript
app.get('/api/dashboard/root/vulnerable', (req, res) => {
    // CRITICAL VULNERABILITY: No role checking for ROOT!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    // Missing: if (user.role !== 'root') return 403;
    res.json({
        rootData: {
            allUsersWithPasswords: users, // ALL PASSWORDS EXPOSED!
            systemSecrets: {...} // CRITICAL SYSTEM DATA!
        }
    });
});
```

## 🔧 The Fix

### Secure Implementation
```javascript
// SECURE VERSION
app.get('/api/dashboard/admin/secure', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    // CRITICAL FIX: Proper role validation
    if (!['admin', 'root'].includes(user.role)) {
        return res.status(403).json({ error: 'Admin privileges required' });
    }
    
    // Safe response with minimal data
    res.json({ message: 'Secure admin access' });
});
```

## 📊 Impact Analysis

### Data Compromised in Root Access
- **All User Passwords**: Plain text passwords for all users
- **Database URL**: `mongodb://root:password123@prod-server:27017/company`
- **AWS Credentials**: Access keys for cloud infrastructure
- **Employee Data**: SSNs, salaries, personal information
- **System Secrets**: Encryption keys, JWT secrets

### Business Impact
- **Complete System Compromise**: Attackers gain full control
- **Data Breach**: All customer and employee data exposed
- **Financial Loss**: Regulatory fines, legal costs, reputation damage
- **Compliance Violations**: GDPR, HIPAA, PCI DSS failures

## 🎬 Demo Script (5 minutes)

### Minute 1: Setup
> "I'll demonstrate how a normal user can escalate privileges to access admin and root functions, exposing critical system data."

**Action**: Show the three user roles and their intended permissions.

### Minute 2: Normal Login
> "First, let's login as a normal user who should only have basic access."

**Action**: Login with `user / password`, show user role in response.

### Minute 3: Admin Escalation
> "Now watch what happens when this normal user tries to access admin functions."

**Action**: Click "Access Admin Dashboard", show exposed system configuration and API keys.

### Minute 4: Root Compromise
> "The real disaster happens when they access root functions."

**Action**: Click "Access Root Dashboard", highlight exposed passwords, database credentials, and AWS keys.

### Minute 5: Code Review
> "This happens because the code only checks if you're logged in, not what role you have."

**Action**: Show vulnerable code vs secure implementation.

## 🔍 Testing Commands

### Manual API Testing
```bash
# 1. Login as normal user
curl -X POST http://localhost:3000/api/login/vulnerable \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' \
  -c cookies.txt

# 2. Access admin endpoint (should fail but doesn't)
curl -X GET http://localhost:3000/api/dashboard/admin/vulnerable \
  -b cookies.txt

# 3. Access root endpoint (catastrophic failure)
curl -X GET http://localhost:3000/api/dashboard/root/vulnerable \
  -b cookies.txt
```

## 📋 Key Takeaways

1. **Authentication ≠ Authorization**: Being logged in doesn't mean you should access everything
2. **Role Validation is Critical**: Always check user roles before granting access
3. **Principle of Least Privilege**: Users should only access what they need
4. **Sensitive Data Handling**: Never expose critical system data in API responses
5. **Defense in Depth**: Multiple security layers prevent single points of failure

## 🚀 Next Steps

1. **Immediate**: Implement proper role-based access control
2. **Short-term**: Add comprehensive logging and monitoring
3. **Long-term**: Regular security audits and penetration testing

---

**Remember**: This is a demonstration of real vulnerabilities found in production systems. Always implement proper security controls!
