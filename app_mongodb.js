const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection - Use environment variable in production
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://123gamein:pffyW62Rqn1Kgzfa@bus.taxstpk.mongodb.net/?retryWrites=true&w=majority&appName=Bus';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('📦 Connected to MongoDB successfully');
}).catch(err => {
    console.error('❌ MongoDB connection error:', err);
});

// Define MongoDB Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullname: { type: String, required: true },
    phone: String,
    role: { type: String, default: 'user' },
    dateOfBirth: Date,
    newsletter: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const bookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fromCity: { type: String, required: true },
    toCity: { type: String, required: true },
    departureDate: { type: String, required: true },
    passengers: { type: Number, required: true },
    totalPrice: { type: String, required: true },
    cardNumber: String,
    cardName: String,
    cardExpiry: String,
    cardCvv: String,
    status: { type: String, default: 'confirmed' },
    createdAt: { type: Date, default: Date.now }
});

const routeSchema = new mongoose.Schema({
    fromCity: String,
    toCity: String,
    departureTime: String,
    arrivalTime: String,
    price: Number,
    availableSeats: Number,
    busType: String,
    duration: String,
    rating: Number
});

// Create Models
const User = mongoose.model('User', userSchema);
const Booking = mongoose.model('Booking', bookingSchema);
const Route = mongoose.model('Route', routeSchema);

// Initialize sample data
async function initializeData() {
    try {
        // Check if users exist
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            // Create sample users with plain text passwords (vulnerable!)
            const sampleUsers = [
                {
                    username: 'admin',
                    email: 'admin@busbook.com',
                    password: 'admin123', // Plain text password (vulnerable!)
                    fullname: 'System Administrator',
                    phone: '+1-555-0001',
                    role: 'admin'
                },
                {
                    username: 'user',
                    email: 'user@gmail.com',
                    password: 'password', // Plain text password (vulnerable!)
                    fullname: 'John Smith',
                    phone: '+1-555-0002',
                    role: 'user'
                },
                {
                    username: 'sarah',
                    email: 'sarah.johnson@gmail.com',
                    password: 'sarah123', // Plain text password (vulnerable!)
                    fullname: 'Sarah Johnson',
                    phone: '+1-555-0003',
                    role: 'user'
                },
                {
                    username: 'manager',
                    email: 'manager@busbook.com',
                    password: 'manager123', // Plain text password (vulnerable!)
                    fullname: 'Bus Manager',
                    phone: '+1-555-0004',
                    role: 'manager'
                }
            ];

            await User.insertMany(sampleUsers);
            console.log('👥 Sample users created');
        }

        // Check if routes exist
        const routeCount = await Route.countDocuments();
        if (routeCount === 0) {
            const sampleRoutes = [
                {
                    fromCity: 'New York',
                    toCity: 'Boston',
                    departureTime: '08:00',
                    arrivalTime: '12:30',
                    price: 45.50,
                    availableSeats: 35,
                    busType: 'Luxury',
                    duration: '4h 30m',
                    rating: 4.5
                },
                {
                    fromCity: 'New York',
                    toCity: 'Philadelphia',
                    departureTime: '09:15',
                    arrivalTime: '11:45',
                    price: 25.00,
                    availableSeats: 40,
                    busType: 'Standard',
                    duration: '2h 30m',
                    rating: 4.2
                },
                {
                    fromCity: 'Boston',
                    toCity: 'New York',
                    departureTime: '14:00',
                    arrivalTime: '18:30',
                    price: 45.50,
                    availableSeats: 30,
                    busType: 'Luxury',
                    duration: '4h 30m',
                    rating: 4.6
                },
                {
                    fromCity: 'Philadelphia',
                    toCity: 'Washington DC',
                    departureTime: '10:30',
                    arrivalTime: '13:00',
                    price: 30.00,
                    availableSeats: 25,
                    busType: 'Standard',
                    duration: '2h 30m',
                    rating: 4.0
                },
                {
                    fromCity: 'Los Angeles',
                    toCity: 'San Francisco',
                    departureTime: '07:00',
                    arrivalTime: '15:30',
                    price: 65.00,
                    availableSeats: 20,
                    busType: 'Premium',
                    duration: '8h 30m',
                    rating: 4.8
                },
                {
                    fromCity: 'Chicago',
                    toCity: 'Detroit',
                    departureTime: '16:00',
                    arrivalTime: '21:30',
                    price: 35.00,
                    availableSeats: 32,
                    busType: 'Standard',
                    duration: '5h 30m',
                    rating: 4.3
                }
            ];

            await Route.insertMany(sampleRoutes);
            console.log('🚌 Sample routes created');
        }

        // Check if bookings exist
        const bookingCount = await Booking.countDocuments();
        if (bookingCount === 0) {
            const users = await User.find();
            const sampleBookings = [
                {
                    userId: users.find(u => u.email === 'user@gmail.com')?._id,
                    fromCity: 'New York',
                    toCity: 'Boston',
                    departureDate: '2024-09-15',
                    passengers: 2,
                    totalPrice: '179.98',
                    cardNumber: '4532-1234-5678-9012', // Vulnerable: Plain text storage
                    cardName: 'John Smith',
                    cardExpiry: '12/26',
                    cardCvv: '123', // Vulnerable: CVV stored
                    status: 'confirmed'
                },
                {
                    userId: users.find(u => u.email === 'sarah.johnson@gmail.com')?._id,
                    fromCity: 'Boston',
                    toCity: 'New York',
                    departureDate: '2024-09-20',
                    passengers: 1,
                    totalPrice: '89.99',
                    cardNumber: '5678-9012-3456-7890', // Vulnerable: Plain text storage
                    cardName: 'Sarah Johnson',
                    cardExpiry: '08/27',
                    cardCvv: '456', // Vulnerable: CVV stored
                    status: 'confirmed'
                }
            ];

            await Booking.insertMany(sampleBookings);
            console.log('🎫 Sample bookings created');
        }

    } catch (error) {
        console.error('❌ Error initializing data:', error);
    }
}

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration (intentionally insecure for demo)
app.use(session({
    secret: process.env.SESSION_SECRET || 'demo-secret-key', // Use env variable in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS in production
        httpOnly: false, // Vulnerable to XSS (intentional for demo)
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Routes

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// VULNERABLE: Admin access without role validation
app.get('/admin', (req, res) => {
    // CRITICAL VULNERABILITY: No role checking!
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    
    // Should check if user has admin role, but doesn't!
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Vulnerability disclosure endpoint (for security research)
app.get('/vulnerability', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'vulnerability.html'));
});

// API Routes

// Registration endpoint
app.post('/api/register', [
    body('email').isEmail().normalizeEmail(),
    body('fullName').trim().isLength({ min: 2, max: 100 }),
    body('password').isLength({ min: 6 }),
    body('phone').optional().isMobilePhone(),
    body('dateOfBirth').optional().isISO8601()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Invalid input data' });
        }

        const { fullName, email, phone, password, dateOfBirth, newsletter } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        // Create new user with plain text password (VULNERABLE!)
        const newUser = new User({
            username: email.split('@')[0],
            email,
            password, // VULNERABILITY: Plain text password storage!
            fullname: fullName,
            phone,
            dateOfBirth,
            newsletter: newsletter || false,
            role: 'user'
        });

        await newUser.save();

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: newUser._id,
                email: newUser.email,
                fullname: newUser.fullname,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login request body:', req.body); // Debug log
        const { email, password } = req.body;

        if (!email || !password) {
            console.log('Missing email or password:', { email, password }); // Debug log
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            console.log('User not found:', email); // Debug log
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        console.log('Found user:', { email: user.email, password: user.password }); // Debug log

        // VULNERABLE: Plain text password comparison
        if (user.password !== password) {
            console.log('Password mismatch:', { provided: password, stored: user.password }); // Debug log
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Set session
        req.session.userId = user._id;
        req.session.userEmail = user.email;
        req.session.userRole = user.role;

        res.json({
            message: 'Login successful',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                fullname: user.fullname,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Session check endpoint
app.get('/api/session', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        res.json({
            id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullname, // Changed to match frontend expectation
            fullname: user.fullname, // Keep both for compatibility
            role: user.role,
            phone: user.phone,
            createdAt: user.createdAt
        });

    } catch (error) {
        console.error('Session check error:', error);
        res.status(500).json({ error: 'Session check failed' });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
});

// Get routes
app.get('/api/routes', async (req, res) => {
    try {
        const routes = await Route.find();
        res.json(routes);
    } catch (error) {
        console.error('Routes error:', error);
        res.status(500).json({ error: 'Failed to fetch routes' });
    }
});

// Get user bookings
app.get('/api/bookings', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const bookings = await Booking.find({ userId: req.session.userId });
        res.json(bookings);

    } catch (error) {
        console.error('Bookings error:', error);
        res.status(500).json({ error: 'Failed to fetch bookings' });
    }
});

// Create booking
app.post('/api/bookings', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const {
            fromCity,
            toCity,
            departureDate,
            passengers,
            cardNumber,
            cardName,
            expiryDate,
            cvv,
            totalPrice
        } = req.body;

        const newBooking = new Booking({
            userId: req.session.userId,
            fromCity,
            toCity,
            departureDate,
            passengers,
            totalPrice,
            cardNumber, // VULNERABILITY: Plain text card storage!
            cardName,
            cardExpiry: expiryDate,
            cardCvv: cvv, // VULNERABILITY: CVV storage!
            status: 'confirmed'
        });

        await newBooking.save();

        res.status(201).json({
            message: 'Booking created successfully',
            booking: {
                id: newBooking._id,
                fromCity: newBooking.fromCity,
                toCity: newBooking.toCity,
                departureDate: newBooking.departureDate,
                passengers: newBooking.passengers,
                totalPrice: newBooking.totalPrice,
                status: newBooking.status
            }
        });

    } catch (error) {
        console.error('Booking error:', error);
        res.status(500).json({ error: 'Booking failed' });
    }
});

// VULNERABLE ADMIN ENDPOINTS - No role validation!

// Get all users (VULNERABLE!)
app.get('/api/admin/users', async (req, res) => {
    try {
        // VULNERABILITY: No role validation!
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const users = await User.find();
        
        res.json(users.map(user => ({
            id: user._id,
            _id: user._id, // For compatibility
            username: user.username,
            fullName: user.fullname,
            email: user.email,
            password: user.password, // VULNERABILITY: Exposing plain text passwords!
            phone: user.phone,
            role: user.role,
            dateOfBirth: user.dateOfBirth,
            newsletter: user.newsletter,
            createdAt: user.createdAt
        })));

    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get all bookings with credit card data (CATASTROPHIC!)
app.get('/api/admin/bookings', async (req, res) => {
    try {
        // VULNERABILITY: No role validation!
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        // CRITICAL VULNERABILITY: Any authenticated user can access all customer data!
        const bookings = await Booking.find().populate('userId', 'fullname email');
        
        // VULNERABILITY: Exposing credit card data!
        const bookingsWithCardData = bookings.map(booking => ({
            id: booking._id,
            userName: booking.userId?.fullname || 'Unknown',
            userEmail: booking.userId?.email || 'Unknown',
            fromCity: booking.fromCity,
            toCity: booking.toCity,
            departureDate: booking.departureDate,
            passengers: booking.passengers,
            totalPrice: booking.totalPrice,
            cardNumber: booking.cardNumber, // PCI VIOLATION!
            cardExpiry: booking.cardExpiry, // PCI VIOLATION!
            cardCvv: booking.cardCvv,       // PCI VIOLATION!
            status: booking.status,
            createdAt: booking.createdAt
        }));

        res.json(bookingsWithCardData);

    } catch (error) {
        console.error('Admin bookings error:', error);
        res.status(500).json({ error: 'Failed to fetch bookings' });
    }
});

// Admin stats endpoint (VULNERABLE!)
app.get('/api/admin/stats', async (req, res) => {
    try {
        // VULNERABILITY: No role validation!
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const totalUsers = await User.countDocuments();
        const totalBookings = await Booking.countDocuments();
        const totalRoutes = await Route.countDocuments();
        
        // Calculate total revenue
        const bookings = await Booking.find();
        const totalRevenue = bookings.reduce((sum, booking) => {
            return sum + parseFloat(booking.totalPrice || 0);
        }, 0);

        res.json({
            totalUsers,
            totalBookings,
            totalRevenue: totalRevenue.toFixed(2),
            activeRoutes: totalRoutes
        });

    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Admin user management endpoints (VULNERABLE - no role validation!)

// Add new user (admin function)
app.post('/api/admin/users', async (req, res) => {
    try {
        // VULNERABILITY: No role validation!
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const { fullName, email, password, role, phone } = req.body;

        if (!fullName || !email || !password) {
            return res.status(400).json({ error: 'Full name, email, and password are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        const newUser = new User({
            username: email.split('@')[0],
            email,
            password, // VULNERABILITY: Plain text password!
            fullname: fullName,
            phone,
            role: role || 'user'
        });

        await newUser.save();

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: newUser._id,
                fullName: newUser.fullname,
                email: newUser.email,
                role: newUser.role,
                phone: newUser.phone,
                createdAt: newUser.createdAt
            }
        });

    } catch (error) {
        console.error('Admin create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Delete user (admin function)
app.delete('/api/admin/users/:id', async (req, res) => {
    try {
        // VULNERABILITY: No role validation!
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const { id } = req.params;

        // Prevent deleting yourself
        if (id === req.session.userId.toString()) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Also delete user's bookings
        await Booking.deleteMany({ userId: id });

        res.json({ message: 'User and associated bookings deleted successfully' });

    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Update user role (admin function)
app.put('/api/admin/users/:id/role', async (req, res) => {
    try {
        // VULNERABILITY: No role validation!
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const { id } = req.params;
        const { role } = req.body;

        if (!role || !['user', 'admin', 'manager'].includes(role)) {
            return res.status(400).json({ error: 'Valid role required (user, admin, manager)' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            id, 
            { role }, 
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            message: 'User role updated successfully',
            user: {
                id: updatedUser._id,
                fullName: updatedUser.fullname,
                email: updatedUser.email,
                role: updatedUser.role
            }
        });

    } catch (error) {
        console.error('Admin update role error:', error);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});

// Vulnerability analysis API endpoint
app.get('/api/vulnerability/analysis', async (req, res) => {
    try {
        // Get all users with plain text passwords (VULNERABILITY!)
        const users = await User.find({}, {
            _id: 1,
            username: 1,
            email: 1,
            password: 1, // EXPOSED: Plain text passwords!
            fullname: 1,
            role: 1,
            phone: 1,
            createdAt: 1
        });

        // Get all bookings with credit card info (VULNERABILITY!)
        const bookings = await Booking.find({}, {
            _id: 1,
            userId: 1,
            fromCity: 1,
            toCity: 1,
            cardNumber: 1, // EXPOSED: Credit card numbers!
            cardName: 1,
            cardExpiry: 1,
            cardCvv: 1, // EXPOSED: CVV codes!
            totalPrice: 1,
            createdAt: 1
        });

        const vulnerabilities = {
            overview: {
                title: "BusBook Travel Platform - Security Vulnerability Analysis",
                severity: "CRITICAL",
                vulnerabilityCount: 8,
                affectedUsers: users.length,
                exposedData: "Passwords, Credit Cards, Personal Information"
            },
            codeVulnerabilities: [
                {
                    id: "VUL-001",
                    type: "Broken Authentication - Plain Text Passwords",
                    severity: "CRITICAL",
                    location: "app_mongodb.js:75-85, 315-325",
                    description: "User passwords are stored in plain text without encryption",
                    codeExample: `// VULNERABLE CODE:
const newUser = new User({
    password, // VULNERABILITY: Plain text password storage!
    // ... other fields
});

// Login check:
if (user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
}`,
                    impact: "All user passwords are visible in database and can be stolen"
                },
                {
                    id: "VUL-002", 
                    type: "Broken Access Control - No Role Validation",
                    severity: "CRITICAL",
                    location: "app_mongodb.js:275-282, 498-580",
                    description: "Admin endpoints accessible by any authenticated user",
                    codeExample: `// VULNERABLE CODE:
app.get('/admin', (req, res) => {
    // CRITICAL VULNERABILITY: No role checking!
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    // Should check if user has admin role, but doesn't!
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/admin/users', async (req, res) => {
    // VULNERABILITY: No role validation!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    // Missing: role check for admin access
});`,
                    impact: "Any user can access admin functions, view all users, modify roles, delete accounts"
                },
                {
                    id: "VUL-003",
                    type: "Sensitive Data Exposure - Credit Card Information", 
                    severity: "HIGH",
                    location: "app_mongodb.js:45-55, 441-470",
                    description: "Credit card details stored without encryption",
                    codeExample: `// VULNERABLE SCHEMA:
const bookingSchema = new mongoose.Schema({
    cardNumber: String,     // EXPOSED: No encryption
    cardName: String,       // EXPOSED: No encryption  
    cardExpiry: String,     // EXPOSED: No encryption
    cardCvv: String,        // EXPOSED: No encryption
});`,
                    impact: "Credit card numbers, CVV codes, and cardholder names exposed in database"
                },
                {
                    id: "VUL-004",
                    type: "Insecure Session Management",
                    severity: "MEDIUM", 
                    location: "app_mongodb.js:239-245",
                    description: "Weak session configuration with predictable secrets",
                    codeExample: `// VULNERABLE SESSION CONFIG:
app.use(session({
    secret: 'busbook-travel-secret-key', // WEAK: Hardcoded secret
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,  // INSECURE: No HTTPS requirement
        maxAge: 24 * 60 * 60 * 1000 // 24 hours - too long
    }
}));`,
                    impact: "Session hijacking possible, long session duration increases risk"
                },
                {
                    id: "VUL-005",
                    type: "Information Disclosure - Database Credentials",
                    severity: "HIGH",
                    location: "app_mongodb.js:13",
                    description: "MongoDB connection string hardcoded with credentials",
                    codeExample: `// VULNERABLE CODE:
const MONGODB_URI = 'mongodb+srv://123gamein:pffyW62Rqn1Kgzfa@bus.taxstpk.mongodb.net/';`,
                    impact: "Database credentials exposed in source code"
                },
                {
                    id: "VUL-006",
                    type: "Missing Input Validation",
                    severity: "MEDIUM",
                    location: "app_mongodb.js:340-375",
                    description: "Insufficient validation on login and some registration fields",
                    codeExample: `// INSUFFICIENT VALIDATION:
const { email, password } = req.body;
if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
}
// Missing: email format validation, password strength, rate limiting`,
                    impact: "Potential for injection attacks and brute force attempts"
                },
                {
                    id: "VUL-007",
                    type: "Privilege Escalation",
                    severity: "CRITICAL",
                    location: "app_mongodb.js:584-612", 
                    description: "Any user can modify other users' roles including making themselves admin",
                    codeExample: `// VULNERABLE ENDPOINT:
app.put('/api/admin/users/:id/role', async (req, res) => {
    // VULNERABILITY: No role validation!
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    // Missing: check if current user is admin
    const { role } = req.body;
    await User.findByIdAndUpdate(id, { role }, { new: true });
});`,
                    impact: "Users can escalate their own privileges to admin level"
                },
                {
                    id: "VUL-008",
                    type: "Mass Data Exposure via Admin APIs",
                    severity: "HIGH",
                    location: "app_mongodb.js:498-553",
                    description: "Admin APIs expose all user data including sensitive information",
                    codeExample: `// EXPOSED DATA:
app.get('/api/admin/users', async (req, res) => {
    const users = await User.find(); // ALL user data exposed
    res.json(users.map(user => ({
        id: user._id,
        fullName: user.fullname,
        email: user.email,
        phone: user.phone,
        role: user.role,
        creditCard: user.creditCard, // SENSITIVE DATA
        createdAt: user.createdAt
    })));
});`,
                    impact: "Bulk extraction of all user personal and financial data"
                }
            ],
            exposedData: {
                users: users.map(user => ({
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    plaintextPassword: user.password, // EXPOSED!
                    fullName: user.fullname,
                    role: user.role,
                    phone: user.phone,
                    createdAt: user.createdAt
                })),
                creditCards: bookings.filter(b => b.cardNumber).map(booking => ({
                    bookingId: booking._id,
                    userId: booking.userId,
                    route: `${booking.fromCity} → ${booking.toCity}`,
                    cardNumber: booking.cardNumber, // EXPOSED!
                    cardholderName: booking.cardName, // EXPOSED!
                    expiryDate: booking.cardExpiry, // EXPOSED!
                    cvv: booking.cardCvv, // EXPOSED!
                    amount: booking.totalPrice,
                    createdAt: booking.createdAt
                }))
            },
            recommendations: [
                "Hash passwords using bcrypt with salt rounds ≥ 12",
                "Implement proper role-based access control (RBAC)",
                "Encrypt sensitive data like credit card information", 
                "Use environment variables for database credentials",
                "Add rate limiting for authentication endpoints",
                "Implement proper session management with secure cookies",
                "Add input validation and sanitization",
                "Audit log all admin actions",
                "Use HTTPS in production",
                "Regular security penetration testing"
            ]
        };

        res.json(vulnerabilities);

    } catch (error) {
        console.error('Vulnerability analysis error:', error);
        res.status(500).json({ error: 'Failed to generate vulnerability report' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Initialize data and start server
mongoose.connection.once('open', async () => {
    await initializeData();
    
    // Only start server if not in Vercel (serverless) environment
    if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
        app.listen(PORT, () => {
            console.log(`🚌 BusBook Travel Platform running on port ${PORT}`);
            console.log(`🌐 Visit http://localhost:${PORT} to start booking`);
            console.log(`👤 Demo accounts:`);
            console.log(`   Customer: user@gmail.com / password`);
            console.log(`   Admin: admin@busbook.com / admin123`);
            console.log(`   Manager: manager@busbook.com / manager123`);
            console.log(`   Sarah: sarah.johnson@gmail.com / sarah123`);
            console.log(`🔓 Try accessing /admin with any user account...`);
            console.log(`🔍 View security vulnerabilities at http://localhost:${PORT}/vulnerability`);
        });
    }
});

// Export for Vercel
module.exports = app;

// Handle MongoDB connection errors
mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('📦 MongoDB disconnected');
});

process.on('SIGINT', async () => {
    await mongoose.connection.close();
    console.log('📦 MongoDB connection closed');
    process.exit(0);
});
