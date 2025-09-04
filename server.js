const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Enhanced login rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: 'Too many login attempts, please try again later'
});

// ================================
// DATABASE MODELS
// ================================

// User Schema
const userSchema = new mongoose.Schema({
    badgeNumber: {
        type: String,
        required: true,
        unique: true,
        match: /^[A-Z]{2}-\d{4}$/ // Format: LS-1234
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstName: {
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        required: true,
        trim: true
    },
    rank: {
        type: String,
        enum: ['Officer', 'Sergeant', 'Lieutenant', 'Captain', 'Deputy Chief', 'Commissioner'],
        default: 'Officer'
    },
    department: {
        type: String,
        enum: ['Traffic', 'Detective', 'SWAT', 'K9', 'Air Support', 'Marine', 'Internal Affairs', 'Motorcycle'],
        required: true
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive', 'Suspended', 'LOA'],
        default: 'Active'
    },
    permissions: [{
        type: String,
        enum: ['dashboard', 'reports', 'evidence', 'personnel', 'admin', 'dispatch', 'armory']
    }],
    profileImage: {
        type: String,
        default: ''
    },
    joinDate: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    },
    loginHistory: [{
        timestamp: Date,
        ip: String,
        userAgent: String
    }],
    isAdmin: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

// Report Schema
const reportSchema = new mongoose.Schema({
    reportNumber: {
        type: String,
        required: true,
        unique: true
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    title: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['Arrest', 'Citation', 'Incident', 'Investigation', 'Use of Force', 'Property', 'Other'],
        required: true
    },
    priority: {
        type: String,
        enum: ['Low', 'Medium', 'High', 'Critical'],
        default: 'Medium'
    },
    location: {
        type: String,
        required: true
    },
    suspects: [{
        name: String,
        age: Number,
        description: String,
        charges: [String]
    }],
    victims: [{
        name: String,
        age: Number,
        description: String
    }],
    witnesses: [{
        name: String,
        contact: String,
        statement: String
    }],
    narrative: {
        type: String,
        required: true
    },
    evidence: [{
        type: String,
        description: String,
        collectedBy: String,
        timestamp: Date
    }],
    status: {
        type: String,
        enum: ['Draft', 'Submitted', 'Under Review', 'Approved', 'Rejected'],
        default: 'Draft'
    },
    reviewedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    reviewNotes: String
}, {
    timestamps: true
});

// Notification Schema
const notificationSchema = new mongoose.Schema({
    recipient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    title: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['info', 'warning', 'success', 'error', 'system'],
        default: 'info'
    },
    read: {
        type: Boolean,
        default: false
    },
    priority: {
        type: String,
        enum: ['low', 'medium', 'high', 'urgent'],
        default: 'medium'
    }
}, {
    timestamps: true
});

// Models
const User = mongoose.model('User', userSchema);
const Report = mongoose.model('Report', reportSchema);
const Notification = mongoose.model('Notification', notificationSchema);

// ================================
// MIDDLEWARE FUNCTIONS
// ================================

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }
        
        if (user.status !== 'Active') {
            return res.status(403).json({ message: 'Account is not active' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

// Admin Authorization Middleware
const requireAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Permission Middleware
const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.user.permissions.includes(permission) && !req.user.isAdmin) {
            return res.status(403).json({ message: `Permission '${permission}' required` });
        }
        next();
    };
};

// ================================
// UTILITY FUNCTIONS
// ================================

// Generate Badge Number
const generateBadgeNumber = async () => {
    let badgeNumber;
    let exists = true;
    
    while (exists) {
        const randomNum = Math.floor(Math.random() * 9000) + 1000;
        badgeNumber = `LS-${randomNum}`;
        exists = await User.findOne({ badgeNumber });
    }
    
    return badgeNumber;
};

// Generate Report Number
const generateReportNumber = async () => {
    const today = new Date();
    const year = today.getFullYear();
    const month = String(today.getMonth() + 1).padStart(2, '0');
    const day = String(today.getDate()).padStart(2, '0');
    
    const prefix = `${year}${month}${day}`;
    
    const count = await Report.countDocuments({
        reportNumber: { $regex: `^${prefix}` }
    });
    
    const sequence = String(count + 1).padStart(4, '0');
    return `${prefix}-${sequence}`;
};

// Send Notification
const sendNotification = async (recipientId, title, message, type = 'info', senderId = null) => {
    try {
        const notification = new Notification({
            recipient: recipientId,
            sender: senderId,
            title,
            message,
            type
        });
        await notification.save();
        return notification;
    } catch (error) {
        console.error('Error sending notification:', error);
    }
};

// ================================
// ROUTES
// ================================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'LSPD Backend is running!' });
});

// Login
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { badgeNumber, password } = req.body;

        if (!badgeNumber || !password) {
            return res.status(400).json({ message: 'Badge number and password are required' });
        }

        const user = await User.findOne({ badgeNumber });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (user.status !== 'Active') {
            return res.status(403).json({ message: 'Account is not active' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Update last login and login history
        user.lastLogin = new Date();
        user.loginHistory.push({
            timestamp: new Date(),
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        
        if (user.loginHistory.length > 10) {
            user.loginHistory = user.loginHistory.slice(-10);
        }
        
        await user.save();

        const token = jwt.sign(
            { userId: user._id, badgeNumber: user.badgeNumber },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                badgeNumber: user.badgeNumber,
                firstName: user.firstName,
                lastName: user.lastName,
                rank: user.rank,
                department: user.department,
                permissions: user.permissions,
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Register (Admin only)
app.post('/api/auth/register', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const {
            email,
            password,
            firstName,
            lastName,
            rank,
            department,
            permissions
        } = req.body;

        if (!email || !password || !firstName || !lastName || !department) {
            return res.status(400).json({ message: 'All required fields must be provided' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }

        const badgeNumber = await generateBadgeNumber();
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({
            badgeNumber,
            email: email.toLowerCase(),
            password: hashedPassword,
            firstName,
            lastName,
            rank: rank || 'Officer',
            department,
            permissions: permissions || ['dashboard']
        });

        await user.save();

        await sendNotification(
            user._id,
            'Welcome to LSPD System',
            `Welcome to the LSPD digital system. Your badge number is ${badgeNumber}.`,
            'success'
        );

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: user._id,
                badgeNumber: user.badgeNumber,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                rank: user.rank,
                department: user.department
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get current user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get dashboard stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const stats = {
            totalOfficers: await User.countDocuments({ status: 'Active' }),
            onDutyOfficers: Math.floor(Math.random() * 50) + 20, // Simulated
            reportsToday: await Report.countDocuments({
                createdAt: { $gte: today }
            }),
            pendingReports: await Report.countDocuments({
                status: { $in: ['Draft', 'Submitted', 'Under Review'] }
            })
        };

        res.json(stats);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ recipient: req.user._id })
            .populate('sender', 'badgeNumber firstName lastName')
            .sort({ createdAt: -1 })
            .limit(20);

        const unreadCount = await Notification.countDocuments({
            recipient: req.user._id,
            read: false
        });

        res.json({
            notifications,
            unreadCount
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get all users (Admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort({ lastName: 1, firstName: 1 });

        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// ================================
// DATABASE CONNECTION & SERVER
// ================================

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB');
        createDefaultAdmin();
    })
    .catch((error) => {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    });

// Create default admin user
const createDefaultAdmin = async () => {
    try {
        const adminExists = await User.findOne({ isAdmin: true });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 12);
            const badgeNumber = await generateBadgeNumber();
            
            const admin = new User({
                badgeNumber,
                email: 'admin@lspd.gov',
                password: hashedPassword,
                firstName: 'System',
                lastName: 'Administrator',
                rank: 'Commissioner',
                department: 'Internal Affairs',
                permissions: ['dashboard', 'reports', 'evidence', 'personnel', 'admin', 'dispatch', 'armory'],
                isAdmin: true
            });

            await admin.save();
            console.log(`🔑 Default admin created!`);
            console.log(`Badge: ${badgeNumber}`);
            console.log(`Email: admin@lspd.gov`);
            console.log(`Password: admin123`);
            console.log(`⚠️  CHANGE PASSWORD AFTER FIRST LOGIN!`);
        }
    } catch (error) {
        console.error('Error creating default admin:', error);
    }
};

// Error handling middleware
app.use((error, req, res, next) => {
    console.error(error);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 LSPD Backend running on port ${PORT}`);
});

module.exports = app;
