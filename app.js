const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://123gamein:pffyW62Rqn1Kgzfa@bus.taxstpk.mongodb.net/?retryWrites=true&w=majority&appName=Bus';

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
        if (row.count === 0) {
            const bookings = [
                {
                    user_id: 2,
                    route: 'New York → Boston',
                    departure_date: '2024-09-15',
                    departure_time: '08:00',
                    passengers: 2,
                    total_amount: 91.00,
                    card_number: '4532-1234-5678-9012',
                    card_expiry: '12/26',
                    card_cvv: '123',
                    passenger_name: 'John Smith',
                    passenger_phone: '+1-555-0002',
                    seat_numbers: 'A1,A2'
                },
                {
                    user_id: 3,
                    route: 'Los Angeles → San Francisco',
                    departure_date: '2024-09-20',
                    departure_time: '07:00',
                    passengers: 1,
                    total_amount: 65.00,
                    card_number: '5555-4444-3333-2222',
                    card_expiry: '08/25',
                    card_cvv: '456',
                    passenger_name: 'Sarah Johnson',
                    passenger_phone: '+1-555-0003',
                    seat_numbers: 'B5'
                },
                {
                    user_id: 2,
                    route: 'Chicago → Detroit',
                    departure_date: '2024-09-25',
                    departure_time: '16:00',
                    passengers: 1,
                    total_amount: 35.00,
                    card_number: '4532-1234-5678-9012',
                    card_expiry: '12/26',
                    card_cvv: '123',
                    passenger_name: 'John Smith',
                    passenger_phone: '+1-555-0002',
                    seat_numbers: 'C3'
                }
            ];

            bookings.forEach(booking => {
                db.run(`INSERT INTO bookings (user_id, route, departure_date, departure_time, passengers, total_amount, card_number, card_expiry, card_cvv, passenger_name, passenger_phone, seat_numbers) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [booking.user_id, booking.route, booking.departure_date, booking.departure_time, booking.passengers, booking.total_amount, booking.card_number, booking.card_expiry, booking.card_cvv, booking.passenger_name, booking.passenger_phone, booking.seat_numbers]);
            });
        }
    });
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Vulnerable session configuration
app.use(session({
    secret: 'busbook-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        httpOnly: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// VULNERABLE: Admin panel accessible without proper role validation
app.get('/admin', (req, res) => {
    // VULNERABILITY: Only checks if user is logged in, not their role
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API Routes

// Register API
app.post('/api/register', [
    body('username').isLength({ min: 3, max: 30 }),
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    body('fullname').isLength({ min: 2 }),
    body('phone').isMobilePhone()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    const { username, email, password, fullname, phone } = req.body;

    // VULNERABILITY: Password stored in plain text
    db.run(`INSERT INTO users (username, email, password, fullname, phone, role) VALUES (?, ?, ?, ?, ?, 'user')`,
        [username, email, password, fullname, phone], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Username or email already exists' });
                }
                return res.status(500).json({ error: 'Registration failed' });
            }
            
            req.session.userId = this.lastID;
            req.session.username = username;
            req.session.role = 'user';
            
            res.json({ 
                message: 'Registration successful',
                redirect: '/dashboard'
            });
        });
});

// Login API
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABILITY: Plain text password comparison
    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, 
        [username, password], (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Login failed' });
            }
            
            if (!user) {
                // VULNERABILITY: Information disclosure
                return res.status(401).json({ error: 'Invalid username or password' });
            }
            
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            
            res.json({ 
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                },
                redirect: user.role === 'admin' ? '/admin' : '/dashboard'
            });
        });
});

// Get user profile
app.get('/api/profile', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.get(`SELECT id, username, email, fullname, phone, role FROM users WHERE id = ?`, 
        [req.session.userId], (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json(user);
        });
});

// Get routes
app.get('/api/routes', (req, res) => {
    db.all(`SELECT * FROM routes`, (err, routes) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch routes' });
        }
        res.json(routes);
    });
});

// Book ticket
app.post('/api/book', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const {
        route, departure_date, departure_time, passengers, total_amount,
        card_number, card_expiry, card_cvv, passenger_name, passenger_phone, seat_numbers
    } = req.body;
    
    // VULNERABILITY: Credit card data stored in plain text
    db.run(`INSERT INTO bookings (user_id, route, departure_date, departure_time, passengers, total_amount, card_number, card_expiry, card_cvv, passenger_name, passenger_phone, seat_numbers) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.session.userId, route, departure_date, departure_time, passengers, total_amount, card_number, card_expiry, card_cvv, passenger_name, passenger_phone, seat_numbers],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Booking failed' });
            }
            
            res.json({
                message: 'Booking successful',
                booking_id: this.lastID
            });
        });
});

// Get user's bookings
app.get('/api/bookings', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.all(`SELECT * FROM bookings WHERE user_id = ? ORDER BY created_at DESC`, 
        [req.session.userId], (err, bookings) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch bookings' });
            }
            res.json(bookings);
        });
});

// VULNERABLE: Admin endpoints - no role validation
app.get('/api/admin/users', (req, res) => {
    // VULNERABILITY: No role validation - any logged in user can access
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // VULNERABILITY: Exposes sensitive user data including passwords
    db.all(`SELECT * FROM users ORDER BY created_at DESC`, (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch users' });
        }
        res.json(users);
    });
});

app.get('/api/admin/bookings', (req, res) => {
    // VULNERABILITY: No role validation
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // VULNERABILITY: Exposes all credit card data
    db.all(`SELECT b.*, u.username, u.email, u.phone as user_phone 
           FROM bookings b 
           JOIN users u ON b.user_id = u.id 
           ORDER BY b.created_at DESC`, (err, bookings) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch bookings' });
        }
        res.json(bookings);
    });
});

app.get('/api/admin/stats', (req, res) => {
    // VULNERABILITY: No role validation
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.get(`SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM bookings) as total_bookings,
        (SELECT SUM(total_amount) FROM bookings) as total_revenue
    `, (err, stats) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch stats' });
        }
        res.json(stats);
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    // VULNERABILITY: Incomplete session cleanup
    req.session.userId = null;
    req.session.username = null;
    req.session.role = null;
    res.json({ message: 'Logged out', redirect: '/' });
});

// Secure endpoints (for comparison)
function requireRole(role) {
    return (req, res, next) => {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        db.get(`SELECT role FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Invalid session' });
            }
            
            if (user.role !== role) {
                return res.status(403).json({ error: 'Insufficient privileges' });
            }
            
            next();
        });
    };
}

// Secure admin endpoints (commented out for demo)
/*
app.get('/api/secure/admin/users', requireRole('admin'), (req, res) => {
    db.all(`SELECT id, username, email, fullname, phone, role, created_at FROM users ORDER BY created_at DESC`, (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch users' });
        }
        res.json(users);
    });
});
*/

app.listen(PORT, () => {
    console.log(`🚌 BusBook Travel Platform running on port ${PORT}`);
    console.log(`🌐 Visit http://localhost:${PORT} to start booking`);
    console.log(`👤 Demo accounts:`);
    console.log(`   Customer: user / password`);
    console.log(`   Admin: admin / admin123`);
    console.log(`🔓 Try accessing /admin with any user account...`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});
