const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory user storage (for demo purposes)
const users = [
    { 
        id: 1, 
        username: 'root', 
        password: 'root',  // Vulnerable: Plain text password
        email: 'root@company.com',
        role: 'root',
        permissions: ['read', 'write', 'delete', 'admin', 'system'],
        salary: 150000,
        ssn: '123-45-6789',
        securePassword: '$2b$10$rFQ3Ox8u7bYjZ1rBq6h5YeKYnwN5kM7U9CJh8X.qP5xK6vL2gE2fG' // bcrypt hash of 'SecurePass123!'
    },
    { 
        id: 2, 
        username: 'admin', 
        password: 'admin123',  // Vulnerable: Plain text password
        email: 'admin@company.com',
        role: 'admin',
        permissions: ['read', 'write', 'delete'],
        salary: 120000,
        ssn: '987-65-4321',
        securePassword: '$2b$10$rFQ3Ox8u7bYjZ1rBq6h5YeKYnwN5kM7U9CJh8X.qP5xK6vL2gE2fG' // bcrypt hash of 'SecurePass123!'
    },
    { 
        id: 3, 
        username: 'user', 
        password: 'password',  // Vulnerable: Weak password
        email: 'user@company.com',
        role: 'user',
        permissions: ['read'],
        salary: 75000,
        ssn: '456-78-9012',
        securePassword: '$2b$10$8H/fK.X2vN9wQ5mE7zP1t.YrL6gA3nU8xS2qW9eR4oI5uT7yV6cB'
    }
];

// Failed login attempts tracker (for demo)
const failedLogins = {};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Security middleware (for secure version)
app.use(helmet({
    contentSecurityPolicy: false // Disabled for demo purposes
}));

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// Rate limiting (for secure version)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: {
        error: 'Too many login attempts, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Session configuration
app.use(session({
    secret: 'vulnerable-secret', // Vulnerable: Weak secret
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Vulnerable: Should be true in HTTPS
        httpOnly: false, // Vulnerable: Should be true
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Secure session configuration (commented out for demo)
const secureSessionConfig = {
    secret: process.env.SESSION_SECRET || uuidv4() + uuidv4(),
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    cookie: {
        secure: process.env.NODE_ENV === 'production', // true in production
        httpOnly: true,
        maxAge: 30 * 60 * 1000, // 30 minutes
        sameSite: 'strict'
    }
};

// Routes

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// VULNERABLE LOGIN ENDPOINT
app.post('/api/login/vulnerable', (req, res) => {
    const { username, password } = req.body;
    
    // Vulnerability 1: No input validation
    // Vulnerability 2: No rate limiting
    // Vulnerability 3: Plain text password comparison
    // Vulnerability 4: Detailed error messages
    // Vulnerability 5: No account lockout
    
    console.log(`Login attempt - Username: ${username}, Password: ${password}`); // Vulnerability: Logging sensitive data
    
    const user = users.find(u => u.username === username);
    
    if (!user) {
        return res.status(401).json({ 
            error: 'Username not found',
            timestamp: new Date().toISOString()
        });
    }
    
    if (user.password !== password) {
        return res.status(401).json({ 
            error: 'Invalid password',
            attempts: failedLogins[username] || 0,
            timestamp: new Date().toISOString()
        });
    }
    
    // Vulnerability 6: Predictable session ID
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    
    res.json({ 
        message: 'Login successful',
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
        },
        session: req.session.id
    });
});

// SECURE LOGIN ENDPOINT
app.post('/api/login/secure', [
    // Input validation
    body('username').isLength({ min: 3, max: 30 }).trim().escape(),
    body('password').isLength({ min: 8, max: 128 })
], loginLimiter, async (req, res) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Invalid input format',
                timestamp: new Date().toISOString()
            });
        }
        
        const { username, password } = req.body;
        
        // Check for account lockout
        const failedAttempts = failedLogins[username] || 0;
        if (failedAttempts >= 5) {
            return res.status(423).json({ 
                error: 'Account temporarily locked due to multiple failed attempts',
                retryAfter: '15 minutes',
                timestamp: new Date().toISOString()
            });
        }
        
        const user = users.find(u => u.username === username);
        
        if (!user) {
            // Generic error message (don't reveal if username exists)
            failedLogins[username] = (failedLogins[username] || 0) + 1;
            return res.status(401).json({ 
                error: 'Invalid credentials',
                timestamp: new Date().toISOString()
            });
        }
        
        // Compare with hashed password
        const isValidPassword = await bcrypt.compare(password, user.securePassword);
        
        if (!isValidPassword) {
            failedLogins[username] = (failedLogins[username] || 0) + 1;
            return res.status(401).json({ 
                error: 'Invalid credentials',
                timestamp: new Date().toISOString()
            });
        }
        
        // Reset failed login attempts on successful login
        delete failedLogins[username];
        
        // Regenerate session ID
        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            req.session.loginTime = new Date().toISOString();
            
            res.json({ 
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                }
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            timestamp: new Date().toISOString()
        });
    }
});

// Dashboard endpoints
app.get('/api/dashboard/vulnerable', (req, res) => {
    // Vulnerability: No session validation
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    res.json({
        message: 'Welcome to vulnerable dashboard',
        user: user,
        session: req.session,
        vulnerabilities: [
            'Session ID exposed in response',
            'Complete user data exposed including sensitive info',
            'No role-based access control validation'
        ]
    });
});

// Vulnerable role-based endpoints
app.get('/api/dashboard/user/vulnerable', (req, res) => {
    // Vulnerability: Weak access control - only checks if user is logged in
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    res.json({
        message: 'User Dashboard Access',
        user: user,
        data: 'User level data access granted',
        vulnerability: 'Any logged-in user can access this endpoint'
    });
});

app.get('/api/dashboard/admin/vulnerable', (req, res) => {
    // Vulnerability: No role validation - any authenticated user can access
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    
    // CRITICAL VULNERABILITY: No role checking!
    res.json({
        message: 'Admin Dashboard Access - PRIVILEGE ESCALATION!',
        user: user,
        adminData: {
            allUsers: users.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role, salary: u.salary })),
            systemConfig: {
                dbPassword: 'super_secret_db_pass',
                apiKeys: ['sk-1234567890', 'ak-0987654321'],
                serverConfig: 'production'
            }
        },
        vulnerability: 'CRITICAL: Any authenticated user can access admin functions!'
    });
});

app.get('/api/dashboard/root/vulnerable', (req, res) => {
    // Vulnerability: No role validation - catastrophic security failure
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    
    // CRITICAL VULNERABILITY: No role checking for ROOT access!
    res.json({
        message: 'ROOT ACCESS GRANTED - SYSTEM COMPROMISED!',
        user: user,
        rootData: {
            allUsersWithPasswords: users, // Exposes all passwords!
            systemSecrets: {
                encryptionKey: 'aes-256-key-super-secret',
                jwtSecret: 'jwt-signing-secret-key',
                databaseUrl: 'mongodb://root:password123@prod-server:27017/company',
                awsCredentials: {
                    accessKey: 'AKIAIOSFODNN7EXAMPLE',
                    secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                }
            },
            employeeRecords: users.map(u => ({
                ...u,
                ssn: u.ssn,
                salary: u.salary,
                performanceReviews: 'Confidential HR data'
            }))
        },
        vulnerability: 'CATASTROPHIC: Root access without authorization - complete system compromise!'
    });
});

app.get('/api/dashboard/secure', (req, res) => {
    // Proper session validation
    if (!req.session.userId || !req.session.loginTime) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Check session timeout (30 minutes)
    const loginTime = new Date(req.session.loginTime);
    const now = new Date();
    const sessionAge = now - loginTime;
    const maxAge = 30 * 60 * 1000; // 30 minutes
    
    if (sessionAge > maxAge) {
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    res.json({
        message: 'Welcome to secure dashboard',
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        }
    });
});

// Secure role-based endpoints with proper access control
app.get('/api/dashboard/user/secure', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    // Proper role validation
    if (!['user', 'admin', 'root'].includes(user.role)) {
        return res.status(403).json({ error: 'Insufficient privileges' });
    }
    
    res.json({
        message: 'User Dashboard - Secure Access',
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        },
        data: 'User level data access granted securely'
    });
});

app.get('/api/dashboard/admin/secure', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    // Proper role validation - only admin and root can access
    if (!['admin', 'root'].includes(user.role)) {
        return res.status(403).json({ error: 'Admin privileges required' });
    }
    
    res.json({
        message: 'Admin Dashboard - Secure Access',
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        },
        adminData: {
            userCount: users.length,
            systemStatus: 'operational'
        }
    });
});

app.get('/api/dashboard/root/secure', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    // Strict role validation - only root can access
    if (user.role !== 'root') {
        return res.status(403).json({ error: 'Root privileges required' });
    }
    
    res.json({
        message: 'Root Dashboard - Secure Access',
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        },
        rootData: {
            systemHealth: 'All systems operational',
            securityStatus: 'No threats detected'
        }
    });
});

// Logout endpoints
app.post('/api/logout/vulnerable', (req, res) => {
    // Vulnerability: Incomplete session cleanup
    req.session.userId = null;
    res.json({ message: 'Logged out' });
});

app.post('/api/logout/secure', (req, res) => {
    // Proper session destruction
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Successfully logged out' });
    });
});

// Password reset (vulnerable)
app.post('/api/reset-password/vulnerable', (req, res) => {
    const { username, newPassword } = req.body;
    
    // Vulnerability: No authentication required for password reset
    // Vulnerability: No email verification
    // Vulnerability: Weak password policy
    
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    user.password = newPassword; // Vulnerability: Store plain text
    
    res.json({ message: 'Password reset successful' });
});

// Admin panel (vulnerable)
app.get('/api/admin/users/vulnerable', (req, res) => {
    // Vulnerability: No role-based access control
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    res.json({ 
        users: users.map(u => ({
            id: u.id,
            username: u.username,
            password: u.password, // Vulnerability: Expose passwords
            email: u.email,
            role: u.role
        }))
    });
});

// Admin panel (secure)
app.get('/api/admin/users/secure', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = users.find(u => u.id === req.session.userId);
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    res.json({ 
        users: users.map(u => ({
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role
            // No password exposure
        }))
    });
});

// Security status endpoint
app.get('/api/security-status', (req, res) => {
    res.json({
        vulnerabilities: [
            {
                id: 'A02:2021',
                name: 'Broken Authentication',
                severity: 'High',
                description: 'Authentication and session management implemented incorrectly',
                examples: [
                    'Weak passwords allowed',
                    'Session IDs exposed in URLs',
                    'Session IDs not rotated after login',
                    'Passwords stored in plain text',
                    'No account lockout mechanisms',
                    'Inadequate session timeout'
                ]
            }
        ],
        fixes: [
            'Implement strong password policies',
            'Use secure session management',
            'Implement account lockout mechanisms',
            'Use multi-factor authentication',
            'Secure password storage with bcrypt',
            'Implement proper session timeout',
            'Use HTTPS for all authentication',
            'Implement rate limiting'
        ]
    });
});

app.listen(PORT, () => {
    console.log(`🚀 OWASP Broken Authentication Demo Server running on port ${PORT}`);
    console.log(`📖 Open http://localhost:${PORT} to view the demonstration`);
    console.log(`🔒 Demo credentials (VULNERABLE):`);
    console.log(`   👤 Normal User: user / password`);
    console.log(`   👨‍💼 Admin User: admin / admin123`);
    console.log(`   🔑 Root User: root / root`);
    console.log(`💡 Secure passwords are: SecurePass123!`);
    console.log(`⚠️  PRIVILEGE ESCALATION DEMO: Normal user can access admin/root dashboards!`);
});
