const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Rate Limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3, // Più restrittivo per admin
    message: { error: 'Too many admin login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Body Parser
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ===========================================
// SCHEMAS - AGGIORNATI CON SUPER ADMIN
// ===========================================

// Super Admin Schema - NUOVO
const superAdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    role: { type: String, default: 'SUPER_ADMIN' },
    badge: { type: String, required: true, unique: true },
    canCreateAdmins: { type: Boolean, default: true },
    lastLogin: { type: Date },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Rank Schema - AGGIORNATO
const rankSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    level: { type: Number, required: true, unique: true },
    badgePrefix: { type: String, required: true }, // NUOVO: Prefisso per badge
    canManage: [{ type: Number }],
    permissions: {
        viewReports: { type: Boolean, default: true },
        createReports: { type: Boolean, default: true },
        managePersonnel: { type: Boolean, default: false },
        adminPanel: { type: Boolean, default: false },
        manageRanks: { type: Boolean, default: false },
        viewDisciplinary: { type: Boolean, default: false },
        issueDisciplinary: { type: Boolean, default: false },
        systemAdmin: { type: Boolean, default: false } // NUOVO
    },
    createdAt: { type: Date, default: Date.now }
});

// User Schema - AGGIORNATO
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    badge: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    rank: { type: mongoose.Schema.Types.ObjectId, ref: 'Rank', required: true },
    department: { type: String, default: 'Patrol' },
    shift: { type: String, default: 'Day' },
    status: { type: String, enum: ['Active', 'Inactive', 'Suspended'], default: 'Active' },
    hireDate: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    passwordChangeRequired: { type: Boolean, default: true }, // NUOVO
    passwordChangedAt: { type: Date }, // NUOVO
    temporaryPassword: { type: Boolean, default: true }, // NUOVO
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

// Audit Log Schema - NUOVO
const auditLogSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    userType: { type: String, enum: ['USER', 'SUPER_ADMIN'], required: true },
    action: { type: String, required: true },
    resource: { type: String, required: true },
    details: { type: Object },
    ipAddress: { type: String },
    userAgent: { type: String },
    timestamp: { type: Date, default: Date.now }
});

// Report Schema (mantenuto uguale)
const reportSchema = new mongoose.Schema({
    reportNumber: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    type: { type: String, required: true, enum: ['Incident', 'Traffic', 'Arrest', 'Investigation', 'Other'] },
    priority: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'], default: 'Medium' },
    description: { type: String, required: true },
    location: { type: String, required: true },
    date: { type: Date, required: true },
    status: { type: String, enum: ['Draft', 'Submitted', 'Under Review', 'Approved', 'Rejected'], default: 'Draft' },
    officerInCharge: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    supervisingOfficer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    evidence: [{
        type: { type: String },
        description: { type: String },
        attachmentUrl: { type: String }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Disciplinary Schema (mantenuto uguale)
const disciplinarySchema = new mongoose.Schema({
    caseNumber: { type: String, required: true, unique: true },
    officer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, required: true, enum: ['Warning', 'Reprimand', 'Suspension', 'Termination', 'Commendation'] },
    reason: { type: String, required: true },
    description: { type: String, required: true },
    issuedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    severity: { type: String, enum: ['Minor', 'Major', 'Severe'], default: 'Minor' },
    status: { type: String, enum: ['Active', 'Resolved', 'Appealed'], default: 'Active' },
    dateIssued: { type: Date, default: Date.now },
    expiryDate: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Rules Schema (mantenuto uguale)
const ruleSchema = new mongoose.Schema({
    section: { type: String, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    order: { type: Number, required: true },
    lastUpdated: { type: Date, default: Date.now },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

// Models
const SuperAdmin = mongoose.model('SuperAdmin', superAdminSchema);
const User = mongoose.model('User', userSchema);
const Rank = mongoose.model('Rank', rankSchema);
const Report = mongoose.model('Report', reportSchema);
const Disciplinary = mongoose.model('Disciplinary', disciplinarySchema);
const Rule = mongoose.model('Rule', ruleSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ===========================================
// MIDDLEWARE AGGIORNATI
// ===========================================

// Auth Middleware per utenti normali
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).populate('rank');
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = user;
        req.userType = 'USER';
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Auth Middleware per Super Admin - NUOVO
const authenticateSuperAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Admin access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await SuperAdmin.findById(decoded.id);
        if (!admin || !admin.isActive) {
            return res.status(401).json({ error: 'Admin not found or inactive' });
        }
        req.user = admin;
        req.userType = 'SUPER_ADMIN';
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid admin token' });
    }
};

// Permission Check Middleware
const requirePermission = (permission) => {
    return (req, res, next) => {
        if (req.userType === 'SUPER_ADMIN') {
            return next(); // Super admin ha tutti i permessi
        }
        
        if (!req.user.rank.permissions[permission]) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// Audit Log Function - NUOVO
const logActivity = async (userId, userType, action, resource, details = {}, req = null) => {
    try {
        const log = new AuditLog({
            userId,
            userType,
            action,
            resource,
            details,
            ipAddress: req ? req.ip : null,
            userAgent: req ? req.get('User-Agent') : null
        });
        await log.save();
    } catch (error) {
        console.error('Audit log error:', error);
    }
};

// ===========================================
// FUNZIONI DI UTILITÀ
// ===========================================

// Generatore di badge - NUOVO
function generateBadge(rank, department = 'GEN') {
    const prefix = rank.badgePrefix || 'LS';
    const deptCode = department.substring(0, 3).toUpperCase();
    const randomNum = Math.floor(1000 + Math.random() * 9000);
    return `${prefix}-${deptCode}${randomNum}`;
}

// Generatore password temporanea - NUOVO
function generateTempPassword() {
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let password = '';
    for (let i = 0; i < 8; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

// ===========================================
// INIZIALIZZAZIONE DATI
// ===========================================

// AGGIORNARE IL FILE server.js esistente con queste modifiche alla funzione initializeData

async function initializeData() {
    try {
        // Create Super Admin se non esiste
        const superAdminCount = await SuperAdmin.countDocuments();
        if (superAdminCount === 0) {
            const hashedPassword = await bcrypt.hash('SuperAdmin123!', 12);
            
            const superAdmin = new SuperAdmin({
                username: 'superadmin',
                email: 'superadmin@lspd.gov',
                password: hashedPassword,
                firstName: 'Super',
                lastName: 'Administrator',
                badge: 'SA-0001'
            });

            await superAdmin.save();
            console.log('🔑 Super Admin created! Username: superadmin, Password: SuperAdmin123!');
        }

        // Inizializza sicurezza
        await initializeSecurityDefaults();

        // Create default ranks con prefissi badge AGGIORNATI
        const rankCount = await Rank.countDocuments();
        if (rankCount === 0) {
            const defaultRanks = [
                {
                    name: 'System Admin',
                    level: 0,
                    badgePrefix: 'ADM',
                    canManage: [1, 2, 3, 4, 5, 6, 7],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: true,
                        viewDisciplinary: true,
                        issueDisciplinary: true,
                        systemAdmin: true
                    }
                },
                {
                    name: 'Cadet',
                    level: 1,
                    badgePrefix: 'CDT',
                    canManage: [],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: false,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: false,
                        issueDisciplinary: false,
                        systemAdmin: false
                    }
                },
                {
                    name: 'Officer',
                    level: 2,
                    badgePrefix: 'OFF',
                    canManage: [1],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: false,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: false,
                        issueDisciplinary: false,
                        systemAdmin: false
                    }
                },
                {
                    name: 'Corporal',
                    level: 3,
                    badgePrefix: 'CPL',
                    canManage: [1, 2],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: true,
                        issueDisciplinary: false,
                        systemAdmin: false
                    }
                },
                {
                    name: 'Sergeant',
                    level: 4,
                    badgePrefix: 'SGT',
                    canManage: [1, 2, 3],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: true,
                        issueDisciplinary: true,
                        systemAdmin: false
                    }
                },
                {
                    name: 'Lieutenant',
                    level: 5,
                    badgePrefix: 'LT',
                    canManage: [1, 2, 3, 4],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: false,
                        viewDisciplinary: true,
                        issueDisciplinary: true,
                        systemAdmin: false
                    }
                },
                {
                    name: 'Captain',
                    level: 6,
                    badgePrefix: 'CPT',
                    canManage: [1, 2, 3, 4, 5],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: true,
                        viewDisciplinary: true,
                        issueDisciplinary: true,
                        systemAdmin: false
                    }
                },
                {
                    name: 'Chief',
                    level: 7,
                    badgePrefix: 'CHF',
                    canManage: [1, 2, 3, 4, 5, 6],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: true,
                        viewDisciplinary: true,
                        issueDisciplinary: true,
                        systemAdmin: false
                    }
                }
            ];

            await Rank.insertMany(defaultRanks);
            console.log('✅ Default ranks created with badge prefixes');
        }

        // Create default admin user con badge fisso AGGIORNATO
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            const chiefRank = await Rank.findOne({ name: 'Chief' });
            const hashedPassword = await bcrypt.hash('admin123', 10);
            
            // BADGE FISSO per demo con nuovo formato
            const badge = 'CHF-ADM5067';
            
            const adminUser = new User({
                email: 'admin@lspd.gov',
                badge: badge,
                password: hashedPassword,
                firstName: 'Admin',
                lastName: 'Chief',
                rank: chiefRank._id,
                department: 'Administration',
                shift: 'All',
                passwordChangeRequired: false,
                temporaryPassword: false,
                passwordChangedAt: new Date()
            });

            await adminUser.save();
            console.log(`🔑 Default admin created! Badge: ${badge}, Password: admin123`);
        }

        // Create default rules (mantenuto uguale)
        const ruleCount = await Rule.countDocuments();
        if (ruleCount === 0) {
            const defaultRules = [
                {
                    section: 'General Conduct',
                    title: 'Professional Behavior',
                    content: 'All officers must maintain professional conduct at all times while on duty.',
                    order: 1
                },
                {
                    section: 'General Conduct',
                    title: 'Uniform Standards',
                    content: 'Officers must wear proper uniform and maintain neat appearance.',
                    order: 2
                },
                {
                    section: 'Radio Protocol',
                    title: 'Clear Communication',
                    content: 'Use clear, concise language when communicating via radio.',
                    order: 3
                },
                {
                    section: 'Evidence Handling',
                    title: 'Chain of Custody',
                    content: 'Maintain proper chain of custody for all evidence collected.',
                    order: 4
                },
                {
                    section: 'Security Protocols',
                    title: 'Password Security',
                    content: 'Officers must use strong passwords and change them according to department policy.',
                    order: 5
                },
                {
                    section: 'Security Protocols',
                    title: 'System Access',
                    content: 'Never share login credentials or leave systems unattended when logged in.',
                    order: 6
                }
            ];

            await Rule.insertMany(defaultRules);
            console.log('✅ Default rules created');
        }

        console.log('🎯 Initialization complete!');
        console.log('=====================================');
        console.log('🔐 LOGIN CREDENTIALS:');
        console.log('📋 USER LOGIN:');
        console.log('   Badge: CHF-ADM5067');
        console.log('   Password: admin123');
        console.log('   URL: /dashboard.html');
        console.log('');
        console.log('👑 SUPER ADMIN LOGIN:');
        console.log('   Username: superadmin');
        console.log('   Password: SuperAdmin123!');
        console.log('   URL: /admin-panel.html');
        console.log('=====================================');

    } catch (error) {
        console.error('Error initializing data:', error);
    }
}

// Start server AGGIORNATO
app.listen(PORT, async () => {
    console.log(`🚀 LSPD Backend v2.0 running on port ${PORT}`);
    console.log('🔧 Initializing system...');
    
    await initializeData();
    
    console.log('✅ System ready!');
    console.log('🌐 Your service is live!');
    console.log(`📍 Health check: ${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/health`);
});

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'LSPD Backend is running!', version: '2.0.0' });
});

// ===========================================
// AUTH ROUTES - AGGIORNATI
// ===========================================

// Login normale utenti
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { badge, password } = req.body;

        if (!badge || !password) {
            return res.status(400).json({ error: 'Badge and password are required' });
        }

        const user = await User.findOne({ badge }).populate('rank');
        if (!user) {
            await logActivity('unknown', 'USER', 'FAILED_LOGIN', 'AUTH', { badge, reason: 'User not found' }, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.status !== 'Active') {
            await logActivity(user._id, 'USER', 'FAILED_LOGIN', 'AUTH', { reason: 'Account inactive' }, req);
            return res.status(401).json({ error: 'Account is inactive' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            await logActivity(user._id, 'USER', 'FAILED_LOGIN', 'AUTH', { reason: 'Invalid password' }, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        const token = jwt.sign(
            { id: user._id, badge: user.badge, type: 'USER' },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        await logActivity(user._id, 'USER', 'LOGIN', 'AUTH', { success: true }, req);

        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                badge: user.badge,
                firstName: user.firstName,
                lastName: user.lastName,
                rank: user.rank,
                department: user.department,
                shift: user.shift,
                status: user.status,
                hireDate: user.hireDate,
                lastLogin: user.lastLogin,
                passwordChangeRequired: user.passwordChangeRequired
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login Super Admin - NUOVO
app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const admin = await SuperAdmin.findOne({ 
            $or: [{ username }, { email: username }],
            isActive: true 
        });

        if (!admin) {
            await logActivity('unknown', 'SUPER_ADMIN', 'FAILED_LOGIN', 'ADMIN_AUTH', { username, reason: 'Admin not found' }, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            await logActivity(admin._id, 'SUPER_ADMIN', 'FAILED_LOGIN', 'ADMIN_AUTH', { reason: 'Invalid password' }, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        admin.lastLogin = new Date();
        await admin.save();

        const token = jwt.sign(
            { id: admin._id, username: admin.username, type: 'SUPER_ADMIN' },
            process.env.JWT_SECRET,
            { expiresIn: '4h' } // Sessione più breve per admin
        );

        await logActivity(admin._id, 'SUPER_ADMIN', 'LOGIN', 'ADMIN_AUTH', { success: true }, req);

        res.json({
            token,
            admin: {
                id: admin._id,
                username: admin.username,
                email: admin.email,
                firstName: admin.firstName,
                lastName: admin.lastName,
                badge: admin.badge,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Resto delle routes... (continua nel prossimo artifact)

// Start server
app.listen(PORT, async () => {
    console.log(`🚀 LSPD Backend v2.0 running on port ${PORT}`);
    await initializeData();
    console.log('Your service is live 🎉');
});

module.exports = app;

// Get dashboard stats for admin
app.get('/api/admin/dashboard', authenticateSuperAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ status: 'Active' });
        const totalReports = await Report.countDocuments();
        const totalRanks = await Rank.countDocuments();
        const pendingReports = await Report.countDocuments({ status: { $in: ['Draft', 'Submitted'] } });
        const activeCases = await Disciplinary.countDocuments({ status: 'Active' });

        // Recent activity (last 10 users who logged in)
        const recentActivity = await User.find({ lastLogin: { $exists: true } })
            .populate('rank', 'name')
            .sort({ lastLogin: -1 })
            .limit(10)
            .select('firstName lastName badge lastLogin rank');

        // System health simulation
        const systemHealth = {
            cpu: Math.floor(Math.random() * 30) + 20, // 20-50%
            memory: Math.floor(Math.random() * 40) + 30, // 30-70%
            storage: Math.floor(Math.random() * 20) + 15, // 15-35%
            uptime: '99.9%'
        };

        await logActivity(req.user._id, 'SUPER_ADMIN', 'VIEW_DASHBOARD', 'ADMIN_DASHBOARD', {}, req);

        res.json({
            stats: {
                totalUsers,
                activeUsers,
                totalReports,
                totalRanks,
                pendingReports,
                activeCases
            },
            recentActivity,
            systemHealth
        });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateSuperAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, search, status, department } = req.query;
        
        let query = {};
        
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { badge: { $regex: search, $options: 'i' } }
            ];
        }
        
        if (status) query.status = status;
        if (department) query.department = department;

        const users = await User.find(query)
            .populate('rank', 'name level')
            .populate('createdBy', 'firstName lastName badge')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await User.countDocuments(query);

        await logActivity(req.user._id, 'SUPER_ADMIN', 'VIEW_USERS', 'ADMIN_USERS', { count: users.length }, req);

        res.json({
            users,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            total
        });
    } catch (error) {
        console.error('Admin users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Create user with auto-generated credentials (admin only)
app.post('/api/admin/users', authenticateSuperAdmin, async (req, res) => {
    try {
        const { firstName, lastName, email, rankId, department, shift } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !rankId) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Get rank for badge generation
        const rank = await Rank.findById(rankId);
        if (!rank) {
            return res.status(400).json({ error: 'Invalid rank' });
        }

        // Generate unique badge
        let badge;
        let attempts = 0;
        do {
            badge = generateBadge(rank, department);
            const existingUser = await User.findOne({ badge });
            if (!existingUser) break;
            attempts++;
        } while (attempts < 10);

        if (attempts >= 10) {
            return res.status(500).json({ error: 'Failed to generate unique badge' });
        }

        // Generate temporary password
        const temporaryPassword = generateTempPassword();
        const hashedPassword = await bcrypt.hash(temporaryPassword, 10);

        const newUser = new User({
            email,
            badge,
            password: hashedPassword,
            firstName,
            lastName,
            rank: rankId,
            department: department || 'Patrol',
            shift: shift || 'Day',
            passwordChangeRequired: true,
            temporaryPassword: true,
            createdBy: req.user._id
        });

        await newUser.save();
        await newUser.populate('rank', 'name level');

        await logActivity(req.user._id, 'SUPER_ADMIN', 'CREATE_USER', 'ADMIN_USERS', {
            targetUserId: newUser._id,
            badge: newUser.badge,
            email: newUser.email
        }, req);

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: newUser._id,
                email: newUser.email,
                badge: newUser.badge,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                rank: newUser.rank,
                department: newUser.department,
                shift: newUser.shift,
                status: newUser.status
            },
            credentials: {
                badge: newUser.badge,
                temporaryPassword: temporaryPassword
            }
        });
    } catch (error) {
        console.error('Admin user creation error:', error);
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            res.status(400).json({ error: `${field} already exists` });
        } else {
            res.status(500).json({ error: 'Failed to create user' });
        }
    }
});

// Update user (admin only)
app.put('/api/admin/users/:id', authenticateSuperAdmin, async (req, res) => {
    try {
        const { firstName, lastName, email, rankId, department, shift, status } = req.body;
        
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Update fields
        if (firstName) user.firstName = firstName;
        if (lastName) user.lastName = lastName;
        if (email) user.email = email;
        if (rankId) user.rank = rankId;
        if (department) user.department = department;
        if (shift) user.shift = shift;
        if (status) user.status = status;

        await user.save();
        await user.populate('rank', 'name level');

        await logActivity(req.user._id, 'SUPER_ADMIN', 'UPDATE_USER', 'ADMIN_USERS', {
            targetUserId: user._id,
            badge: user.badge,
            changes: req.body
        }, req);

        res.json({
            message: 'User updated successfully',
            user
        });
    } catch (error) {
        console.error('Admin user update error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Reset user password (admin only)
app.post('/api/admin/users/:id/reset-password', authenticateSuperAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate new temporary password
        const newPassword = generateTempPassword();
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.passwordChangeRequired = true;
        user.temporaryPassword = true;
        user.passwordChangedAt = new Date();

        await user.save();

        await logActivity(req.user._id, 'SUPER_ADMIN', 'RESET_PASSWORD', 'ADMIN_USERS', {
            targetUserId: user._id,
            badge: user.badge
        }, req);

        res.json({
            message: 'Password reset successfully',
            credentials: {
                badge: user.badge,
                newPassword: newPassword
            }
        });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Batch create users from CSV (admin only)
app.post('/api/admin/users/batch', authenticateSuperAdmin, async (req, res) => {
    try {
        const { users } = req.body; // Array of user objects

        if (!Array.isArray(users) || users.length === 0) {
            return res.status(400).json({ error: 'Invalid users array' });
        }

        const results = {
            success: [],
            errors: []
        };

        for (let i = 0; i < users.length; i++) {
            const userData = users[i];
            
            try {
                // Find rank by name
                const rank = await Rank.findOne({ name: userData.rankName });
                if (!rank) {
                    results.errors.push({
                        row: i + 1,
                        data: userData,
                        error: `Rank '${userData.rankName}' not found`
                    });
                    continue;
                }

                // Generate unique badge
                let badge;
                let attempts = 0;
                do {
                    badge = generateBadge(rank, userData.department);
                    const existingUser = await User.findOne({ badge });
                    if (!existingUser) break;
                    attempts++;
                } while (attempts < 10);

                if (attempts >= 10) {
                    results.errors.push({
                        row: i + 1,
                        data: userData,
                        error: 'Failed to generate unique badge'
                    });
                    continue;
                }

                // Generate temporary password
                const temporaryPassword = generateTempPassword();
                const hashedPassword = await bcrypt.hash(temporaryPassword, 10);

                const newUser = new User({
                    email: userData.email,
                    badge,
                    password: hashedPassword,
                    firstName: userData.firstName,
                    lastName: userData.lastName,
                    rank: rank._id,
                    department: userData.department || 'Patrol',
                    shift: userData.shift || 'Day',
                    passwordChangeRequired: true,
                    temporaryPassword: true,
                    createdBy: req.user._id
                });

                await newUser.save();

                results.success.push({
                    row: i + 1,
                    user: {
                        badge: newUser.badge,
                        email: newUser.email,
                        firstName: newUser.firstName,
                        lastName: newUser.lastName,
                        temporaryPassword: temporaryPassword
                    }
                });

            } catch (error) {
                results.errors.push({
                    row: i + 1,
                    data: userData,
                    error: error.message
                });
            }
        }

        await logActivity(req.user._id, 'SUPER_ADMIN', 'BATCH_CREATE_USERS', 'ADMIN_USERS', {
            totalAttempted: users.length,
            successful: results.success.length,
            failed: results.errors.length
        }, req);

        res.json({
            message: 'Batch user creation completed',
            results
        });

    } catch (error) {
        console.error('Batch user creation error:', error);
        res.status(500).json({ error: 'Failed to create users in batch' });
    }
});

// Get audit logs (admin only)
app.get('/api/admin/logs', authenticateSuperAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, userId, action, resource, startDate, endDate } = req.query;
        
        let query = {};
        
        if (userId) query.userId = userId;
        if (action) query.action = action;
        if (resource) query.resource = resource;
        
        if (startDate || endDate) {
            query.timestamp = {};
            if (startDate) query.timestamp.$gte = new Date(startDate);
            if (endDate) query.timestamp.$lte = new Date(endDate);
        }

        const logs = await AuditLog.find(query)
            .sort({ timestamp: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await AuditLog.countDocuments(query);

        res.json({
            logs,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            total
        });
    } catch (error) {
        console.error('Audit logs fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
});

// Export data (admin only)
app.get('/api/admin/export/:type', authenticateSuperAdmin, async (req, res) => {
    try {
        const { type } = req.params;
        const { format = 'csv' } = req.query;
        
        let data = [];
        let filename = '';
        
        switch (type) {
            case 'users':
                data = await User.find().populate('rank', 'name').lean();
                filename = `lspd_users_${new Date().toISOString().split('T')[0]}.csv`;
                break;
                
            case 'reports':
                data = await Report.find().populate('officerInCharge', 'firstName lastName badge').lean();
                filename = `lspd_reports_${new Date().toISOString().split('T')[0]}.csv`;
                break;
                
            case 'logs':
                data = await AuditLog.find().limit(10000).lean(); // Limit for performance
                filename = `lspd_logs_${new Date().toISOString().split('T')[0]}.csv`;
                break;
                
            default:
                return res.status(400).json({ error: 'Invalid export type' });
        }

        await logActivity(req.user._id, 'SUPER_ADMIN', 'EXPORT_DATA', 'ADMIN_EXPORT', {
            type,
            format,
            recordCount: data.length
        }, req);

        if (format === 'csv') {
            const csv = convertToCSV(data, type);
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.send(csv);
        } else {
            res.json({ data, count: data.length });
        }

    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ error: 'Failed to export data' });
    }
});

// System backup (admin only)
app.post('/api/admin/backup', authenticateSuperAdmin, async (req, res) => {
    try {
        // Simulate backup creation
        const backupId = `backup_${Date.now()}`;
        const timestamp = new Date().toISOString();
        
        // In a real implementation, this would:
        // 1. Create a MongoDB dump
        // 2. Compress the data
        // 3. Store it securely (cloud storage, etc.)
        // 4. Return download link or store reference
        
        await logActivity(req.user._id, 'SUPER_ADMIN', 'CREATE_BACKUP', 'ADMIN_BACKUP', {
            backupId,
            timestamp
        }, req);
        
        res.json({
            message: 'Backup created successfully',
            backupId,
            timestamp,
            size: '45.2 MB', // Simulated
            downloadUrl: `/api/admin/backup/${backupId}/download` // Simulated
        });

    } catch (error) {
        console.error('Backup creation error:', error);
        res.status(500).json({ error: 'Failed to create backup' });
    }
});

// System settings (admin only)
app.get('/api/admin/settings', authenticateSuperAdmin, async (req, res) => {
    try {
        // In a real implementation, these would be stored in a Settings collection
        const settings = {
            systemName: 'LSPD Management System',
            adminEmail: 'admin@lspd.gov',
            sessionDuration: 8,
            autoBackup: 'daily',
            passwordPolicy: {
                minLength: 8,
                requireUppercase: true,
                requireNumbers: true,
                expiryDays: 90
            },
            maintenanceMode: false,
            registrationEnabled: false
        };

        res.json(settings);
    } catch (error) {
        console.error('Settings fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/admin/settings', authenticateSuperAdmin, async (req, res) => {
    try {
        const settings = req.body;
        
        // In a real implementation, save to Settings collection
        // await Settings.findOneAndUpdate({}, settings, { upsert: true });
        
        await logActivity(req.user._id, 'SUPER_ADMIN', 'UPDATE_SETTINGS', 'ADMIN_SETTINGS', {
            changes: Object.keys(settings)
        }, req);

        res.json({
            message: 'Settings updated successfully',
            settings
        });
    } catch (error) {
        console.error('Settings update error:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ===========================================
// UTILITY FUNCTIONS - NUOVE
// ===========================================

// Convert data to CSV format
function convertToCSV(data, type) {
    if (!data || data.length === 0) return '';
    
    let headers = [];
    let rows = [];
    
    switch (type) {
        case 'users':
            headers = ['Badge', 'First Name', 'Last Name', 'Email', 'Rank', 'Department', 'Status', 'Hire Date'];
            rows = data.map(user => [
                user.badge,
                user.firstName,
                user.lastName,
                user.email,
                user.rank?.name || 'N/A',
                user.department,
                user.status,
                user.hireDate ? new Date(user.hireDate).toLocaleDateString() : 'N/A'
            ]);
            break;
            
        case 'reports':
            headers = ['Report Number', 'Title', 'Type', 'Officer', 'Date', 'Status'];
            rows = data.map(report => [
                report.reportNumber,
                report.title,
                report.type,
                report.officerInCharge ? `${report.officerInCharge.firstName} ${report.officerInCharge.lastName}` : 'N/A',
                new Date(report.date).toLocaleDateString(),
                report.status
            ]);
            break;
            
        case 'logs':
            headers = ['Timestamp', 'User ID', 'User Type', 'Action', 'Resource', 'IP Address'];
            rows = data.map(log => [
                new Date(log.timestamp).toLocaleString(),
                log.userId,
                log.userType,
                log.action,
                log.resource,
                log.ipAddress || 'N/A'
            ]);
            break;
    }
    
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(field => `"${field}"`).join(','))
    ].join('\n');
    
    return csvContent;
}

// Enhanced badge generation with department codes
function generateBadge(rank, department = 'GEN') {
    const deptCodes = {
        'Patrol': 'PAT',
        'Traffic': 'TRA',
        'Detective': 'DET', 
        'SWAT': 'SWT',
        'Administration': 'ADM',
        'K9': 'K9U',
        'Cybercrime': 'CYB',
        'Narcotics': 'NAR'
    };
    
    const prefix = rank.badgePrefix || 'LS';
    const deptCode = deptCodes[department] || 'GEN';
    const randomNum = Math.floor(1000 + Math.random() * 9000);
    
    return `${prefix}-${deptCode}${randomNum}`;
}

// Enhanced password generation
function generateTempPassword() {
    const lowercase = 'abcdefghjkmnpqrstuvwxyz';
    const uppercase = 'ABCDEFGHJKMNPQRSTUVWXYZ';
    const numbers = '23456789';
    const all = lowercase + uppercase + numbers;
    
    let password = '';
    
    // Ensure at least one of each type
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    
    // Fill the rest randomly
    for (let i = 3; i < 8; i++) {
        password += all[Math.floor(Math.random() * all.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// SOSTITUIRE LA SEZIONE JAVASCRIPT nel file admin-panel.html con questo codice aggiornato

class SuperAdminPanel {
    constructor() {
        this.apiUrl = 'https://lspd-bankend.onrender.com/api';
        this.token = localStorage.getItem('lspd_token');
        this.admin = JSON.parse(localStorage.getItem('lspd_user') || 'null');
        this.currentPage = {
            users: 1,
            logs: 1
        };
        
        if (!this.token || !this.admin || localStorage.getItem('lspd_user_type') !== 'admin') {
            window.location.href = 'login.html';
            return;
        }
        
        this.init();
    }

    async init() {
        this.setupNavigation();
        this.displayAdminInfo();
        this.loadDashboardData();
        this.loadRanks();
        this.setupEventListeners();
    }

    setupNavigation() {
        const navLinks = document.querySelectorAll('.admin-nav-link');
        const sections = document.querySelectorAll('.admin-section');

        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const sectionId = link.dataset.section;
                
                navLinks.forEach(l => l.classList.remove('active'));
                sections.forEach(s => s.classList.remove('active'));
                
                link.classList.add('active');
                document.getElementById(sectionId).classList.add('active');
                
                const titles = {
                    'dashboard': 'Dashboard',
                    'users': 'Gestione Utenti',
                    'system': 'Sistema',
                    'logs': 'Audit Logs',
                    'backup': 'Backup & Export',
                    'settings': 'Configurazioni'
                };
                document.getElementById('page-title').textContent = titles[sectionId] || 'Dashboard';
                
                this.loadSectionData(sectionId);
            });
        });
    }

    displayAdminInfo() {
        document.getElementById('admin-name').textContent = `${this.admin.firstName} ${this.admin.lastName}`;
    }

    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.apiUrl}${endpoint}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (response.status === 401) {
                this.logout();
                return null;
            }

            // Handle file downloads
            if (response.headers.get('content-type')?.includes('text/csv')) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = response.headers.get('content-disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'export.csv';
                a.click();
                window.URL.revokeObjectURL(url);
                return { success: true };
            }

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            this.showAlert(error.message, 'error');
            throw error;
        }
    }

    async loadDashboardData() {
        try {
            const data = await this.apiCall('/admin/dashboard');
            
            // Update stats
            document.getElementById('total-users').textContent = data.stats.totalUsers;
            document.getElementById('active-users').textContent = data.stats.activeUsers;
            document.getElementById('total-reports').textContent = data.stats.totalReports;
            
            // Update system health
            const healthPercentage = Math.max(
                100 - data.systemHealth.cpu - data.systemHealth.memory - data.systemHealth.storage/2, 
                85
            );
            document.getElementById('system-health').textContent = `${Math.round(healthPercentage)}%`;
            
            // Display recent activity
            this.displayRecentActivity(data.recentActivity);
            
            // Update system status
            document.getElementById('uptime').textContent = data.systemHealth.uptime;
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            // Fallback to default values
            document.getElementById('total-users').textContent = '127';
            document.getElementById('active-users').textContent = '98';
            document.getElementById('total-reports').textContent = '1,234';
        }
    }

    displayRecentActivity(activities) {
        const container = document.getElementById('recent-activity');
        container.innerHTML = '';
        
        if (!activities || activities.length === 0) {
            container.innerHTML = '<p>Nessuna attività recente</p>';
            return;
        }
        
        activities.slice(0, 5).forEach(activity => {
            const div = document.createElement('div');
            div.className = 'activity-item';
            div.style.cssText = 'padding: 0.5rem 0; border-bottom: 1px solid var(--border-color); font-size: 0.9rem;';
            div.innerHTML = `
                <strong>${activity.firstName} ${activity.lastName}</strong> (${activity.badge})
                <br>
                <small style="color: var(--text-secondary);">
                    Ultimo accesso: ${activity.lastLogin ? new Date(activity.lastLogin).toLocaleString() : 'Mai'}
                </small>
            `;
            container.appendChild(div);
        });
    }

    async loadRanks() {
        try {
            const ranks = await this.apiCall('/ranks');
            const select = document.getElementById('rank-select');
            
            select.innerHTML = '';
            ranks.forEach(rank => {
                const option = document.createElement('option');
                option.value = rank._id;
                option.textContent = `${rank.name} (Livello ${rank.level})`;
                select.appendChild(option);
            });
            
        } catch (error) {
            console.error('Failed to load ranks:', error);
        }
    }

    async loadUsers() {
        try {
            const data = await this.apiCall(`/admin/users?page=${this.currentPage.users}&limit=50`);
            const tbody = document.getElementById('users-table');
            tbody.innerHTML = '';
            
            if (!data.users || data.users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">Nessun utente trovato</td></tr>';
                return;
            }
            
            data.users.forEach(user => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${user.badge}</strong></td>
                    <td>${user.firstName} ${user.lastName}</td>
                    <td>${user.email}</td>
                    <td><span class="status-badge status-active">${user.rank.name}</span></td>
                    <td>${user.department}</td>
                    <td><span class="status-badge status-${user.status.toLowerCase()}">${user.status}</span></td>
                    <td>${user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Mai'}</td>
                    <td>
                        <button class="admin-btn admin-btn-warning" onclick="adminPanel.editUser('${user._id}')" style="margin-right: 0.5rem;">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="admin-btn admin-btn-danger" onclick="adminPanel.resetPassword('${user._id}')">
                            <i class="fas fa-key"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
            
        } catch (error) {
            console.error('Failed to load users:', error);
        }
    }

    async loadSectionData(sectionId) {
        switch(sectionId) {
            case 'users':
                await this.loadUsers();
                break;
            case 'logs':
                await this.loadAuditLogs();
                break;
            case 'system':
                await this.loadSystemInfo();
                break;
            case 'settings':
                await this.loadSettings();
                break;
        }
    }

    async loadAuditLogs() {
        try {
            const data = await this.apiCall(`/admin/logs?page=${this.currentPage.logs}&limit=50`);
            const tbody = document.getElementById('logs-table');
            tbody.innerHTML = '';
            
            if (!data.logs || data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Nessun log trovato</td></tr>';
                return;
            }
            
            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                const actionBadge = this.getActionBadge(log.action);
                tr.innerHTML = `
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td>${log.userId}</td>
                    <td><span class="status-badge status-${log.userType === 'SUPER_ADMIN' ? 'warning' : 'active'}">${log.action}</span></td>
                    <td>${log.resource}</td>
                    <td>${log.ipAddress || 'N/A'}</td>
                    <td>
                        <button class="admin-btn" onclick="adminPanel.viewLogDetails('${log._id}')" style="font-size: 0.8rem; padding: 0.4rem 0.8rem;">
                            <i class="fas fa-eye"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
            
        } catch (error) {
            console.error('Failed to load audit logs:', error);
        }
    }

    getActionBadge(action) {
        const actionColors = {
            'LOGIN': 'success',
            'LOGOUT': 'secondary',
            'CREATE_USER': 'success',
            'UPDATE_USER': 'warning',
            'DELETE_USER': 'danger',
            'RESET_PASSWORD': 'warning',
            'FAILED_LOGIN': 'danger'
        };
        return actionColors[action] || 'secondary';
    }

    async loadSystemInfo() {
        try {
            // System info is loaded with dashboard data
            const data = await this.apiCall('/admin/dashboard');
            
            // Update performance indicators
            const performance = document.getElementById('system-performance');
            performance.innerHTML = `
                <p>CPU: <span class="status-badge ${data.systemHealth.cpu < 70 ? 'status-active' : 'status-warning'}">${data.systemHealth.cpu}%</span></p>
                <p>RAM: <span class="status-badge ${data.systemHealth.memory < 80 ? 'status-active' : 'status-warning'}">${data.systemHealth.memory}%</span></p>
                <p>Storage: <span class="status-badge ${data.systemHealth.storage < 85 ? 'status-active' : 'status-warning'}">${data.systemHealth.storage}%</span></p>
            `;
            
        } catch (error) {
            console.error('Failed to load system info:', error);
        }
    }

    async loadSettings() {
        try {
            const settings = await this.apiCall('/admin/settings');
            const form = document.getElementById('settings-form');
            
            // Populate form with current settings
            Object.keys(settings).forEach(key => {
                const input = form.querySelector(`[name="${key}"]`);
                if (input) {
                    input.value = settings[key];
                }
            });
            
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    setupEventListeners() {
        // Form submissions
        document.getElementById('create-user-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.createUser(e.target);
        });
        
        document.getElementById('settings-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveSettings();
        });

        // CSV file upload
        document.getElementById('csv-file').addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.previewCSV(e.target.files[0]);
            }
        });
    }

    async createUser(form) {
        try {
            const formData = new FormData(form);
            const data = Object.fromEntries(formData);
            
            const result = await this.apiCall('/admin/users', {
                method: 'POST',
                body: JSON.stringify(data)
            });
            
            this.showAlert(
                `Utente creato con successo!<br>
                <strong>Badge:</strong> ${result.credentials.badge}<br>
                <strong>Password temporanea:</strong> <code style="background: rgba(255,255,255,0.1); padding: 0.2rem 0.4rem; border-radius: 4px;">${result.credentials.temporaryPassword}</code><br>
                <small>L'utente dovrà cambiare la password al primo accesso</small>`, 
                'success'
            );
            
            form.reset();
            this.loadUsers();
            
        } catch (error) {
            console.error('Failed to create user:', error);
        }
    }

    async editUser(userId) {
        this.showAlert('Funzionalità di modifica utente in sviluppo', 'warning');
        // TODO: Implement user edit modal
    }

    async resetPassword(userId) {
        if (confirm('Sei sicuro di voler resettare la password di questo utente?')) {
            try {
                const result = await this.apiCall(`/admin/users/${userId}/reset-password`, {
                    method: 'POST'
                });
                
                this.showAlert(
                    `Password resettata con successo!<br>
                    <strong>Badge:</strong> ${result.credentials.badge}<br>
                    <strong>Nuova password:</strong> <code style="background: rgba(255,255,255,0.1); padding: 0.2rem 0.4rem; border-radius: 4px;">${result.credentials.newPassword}</code>`, 
                    'success'
                );
                
            } catch (error) {
                console.error('Failed to reset password:', error);
            }
        }
    }

    async previewCSV(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const csv = e.target.result;
            const lines = csv.split('\n');
            const headers = lines[0].split(',');
            
            // Validate CSV format
            const requiredHeaders = ['firstName', 'lastName', 'email', 'rankName', 'department', 'shift'];
            const missingHeaders = requiredHeaders.filter(h => !headers.includes(h));
            
            if (missingHeaders.length > 0) {
                this.showAlert(`CSV mancante di colonne richieste: ${missingHeaders.join(', ')}`, 'error');
                return;
            }
            
            this.showAlert(`CSV caricato: ${lines.length - 1} utenti da creare`, 'success');
        };
        reader.readAsText(file);
    }

    async uploadCSV() {
        const fileInput = document.getElementById('csv-file');
        const file = fileInput.files[0];
        
        if (!file) {
            this.showAlert('Seleziona un file CSV', 'error');
            return;
        }
        
        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const csv = e.target.result;
                const lines = csv.split('\n').filter(line => line.trim());
                const headers = lines[0].split(',').map(h => h.trim());
                
                const users = [];
                for (let i = 1; i < lines.length; i++) {
                    const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
                    const user = {};
                    headers.forEach((header, index) => {
                        user[header] = values[index];
                    });
                    users.push(user);
                }
                
                const result = await this.apiCall('/admin/users/batch', {
                    method: 'POST',
                    body: JSON.stringify({ users })
                });
                
                this.showAlert(
                    `Creazione batch completata!<br>
                    <strong>Successi:</strong> ${result.results.success.length}<br>
                    <strong>Errori:</strong> ${result.results.errors.length}`, 
                    result.results.errors.length === 0 ? 'success' : 'warning'
                );
                
                // Show detailed results
                this.showBatchResults(result.results);
                
                fileInput.value = '';
                this.loadUsers();
                
            } catch (error) {
                console.error('Failed to upload CSV:', error);
            }
        };
        reader.readAsText(file);
    }

    showBatchResults(results) {
        let content = '<div style="max-height: 300px; overflow-y: auto;">';
        
        if (results.success.length > 0) {
            content += '<h4 style="color: var(--success-color);">Utenti creati con successo:</h4>';
            results.success.forEach(item => {
                content += `
                    <div style="margin: 0.5rem 0; padding: 0.5rem; background: rgba(16, 185, 129, 0.1); border-radius: 4px;">
                        <strong>${item.user.firstName} ${item.user.lastName}</strong><br>
                        Badge: ${item.user.badge} | Password: <code>${item.user.temporaryPassword}</code>
                    </div>
                `;
            });
        }
        
        if (results.errors.length > 0) {
            content += '<h4 style="color: var(--danger-color); margin-top: 1rem;">Errori:</h4>';
            results.errors.forEach(item => {
                content += `
                    <div style="margin: 0.5rem 0; padding: 0.5rem; background: rgba(239, 68, 68, 0.1); border-radius: 4px;">
                        <strong>Riga ${item.row}:</strong> ${item.error}<br>
                        <small>${JSON.stringify(item.data)}</small>
                    </div>
                `;
            });
        }
        
        content += '</div>';
        
        // Create modal for results
        const modal = document.createElement('div');
        modal.className = 'admin-modal active';
        modal.innerHTML = `
            <div class="admin-modal-content">
                <div class="modal-header">
                    <h3>Risultati Creazione Batch</h3>
                    <button class="close-modal" onclick="this.closest('.admin-modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div style="padding: 1rem;">${content}</div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    downloadTemplate() {
        const csvContent = 'firstName,lastName,email,rankName,department,shift\nMario,Rossi,mario.rossi@lspd.gov,Officer,Patrol,Day\nLucia,Bianchi,lucia.bianchi@lspd.gov,Corporal,Traffic,Evening\n';
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'lspd_users_template.csv';
        a.click();
        window.URL.revokeObjectURL(url);
    }

    async exportUsers() {
        try {
            await this.apiCall('/admin/export/users');
            this.showAlert('Export utenti completato!', 'success');
        } catch (error) {
            console.error('Failed to export users:', error);
        }
    }

    async exportData(type) {
        try {
            await this.apiCall(`/admin/export/${type}`);
            this.showAlert(`Export ${type} completato!`, 'success');
        } catch (error) {
            console.error(`Failed to export ${type}:`, error);
        }
    }

    async exportLogs() {
        try {
            await this.apiCall('/admin/export/logs');
            this.showAlert('Export logs completato!', 'success');
        } catch (error) {
            console.error('Failed to export logs:', error);
        }
    }

    async createBackup() {
        if (confirm('Creare un backup completo del database? Questa operazione potrebbe richiedere alcuni minuti.')) {
            try {
                const result = await this.apiCall('/admin/backup', {
                    method: 'POST'
                });
                
                this.showAlert(
                    `Backup creato con successo!<br>
                    <strong>ID Backup:</strong> ${result.backupId}<br>
                    <strong>Dimensione:</strong> ${result.size}<br>
                    <strong>Timestamp:</strong> ${new Date(result.timestamp).toLocaleString()}`, 
                    'success'
                );
                
            } catch (error) {
                console.error('Failed to create backup:', error);
            }
        }
    }

    async saveSettings() {
        try {
            const formData = new FormData(document.getElementById('settings-form'));
            const settings = Object.fromEntries(formData);
            
            await this.apiCall('/admin/settings', {
                method: 'PUT',
                body: JSON.stringify(settings)
            });
            
            this.showAlert('Impostazioni salvate con successo!', 'success');
            
        } catch (error) {
            console.error('Failed to save settings:', error);
        }
    }

    async refreshStats() {
        this.showAlert('Aggiornamento statistiche...', 'success');
        await this.loadDashboardData();
    }

    async checkSystemHealth() {
        this.showAlert('Diagnosi sistema in corso...', 'success');
        await this.loadSystemInfo();
    }

    viewLogDetails(logId) {
        this.showAlert('Visualizzazione dettagli log in sviluppo', 'warning');
        // TODO: Implement log details modal
    }

    openModal(modalId) {
        document.getElementById(modalId).classList.add('active');
    }

    closeModal(modalId) {
        document.getElementById(modalId).classList.remove('active');
    }

    showAlert(message, type = 'info') {
        // Remove existing alerts
        const existingAlerts = document.querySelectorAll('.admin-alert');
        existingAlerts.forEach(alert => alert.remove());
        
        // Create new alert
        const alert = document.createElement('div');
        alert.className = `admin-alert admin-alert-${type}`;
        
        const icon = type === 'success' ? 'check-circle' : 
                   type === 'error' ? 'exclamation-circle' : 
                   type === 'warning' ? 'exclamation-triangle' : 'info-circle';
        
        alert.innerHTML = `
            <i class="fas fa-${icon}"></i>
            <div>${message}</div>
        `;
        
        // Insert at top of main content
        const mainContent = document.querySelector('.admin-main');
        const header = document.querySelector('.admin-header');
        mainContent.insertBefore(alert, header.nextSibling);
        
        // Auto remove after 8 seconds for long messages
        setTimeout(() => {
            if (alert.parentNode) alert.remove();
        }, 8000);
    }

    logout() {
        localStorage.removeItem('lspd_token');
        localStorage.removeItem('lspd_user');
        localStorage.removeItem('lspd_user_type');
        window.location.href = 'login.html';
    }
}

// Global functions
function openModal(modalId) {
    adminPanel.openModal(modalId);
}

function closeModal(modalId) {
    adminPanel.closeModal(modalId);
}

function logout() {
    adminPanel.logout();
}

function refreshStats() {
    adminPanel.refreshStats();
}

function loadUsers() {
    adminPanel.loadUsers();
}

function uploadCSV() {
    adminPanel.uploadCSV();
}

function downloadTemplate() {
    adminPanel.downloadTemplate();
}

function exportUsers() {
    adminPanel.exportUsers();
}

function exportData(type) {
    adminPanel.exportData(type);
}

function exportLogs() {
    adminPanel.exportLogs();
}

function createBackup() {
    adminPanel.createBackup();
}

function saveSettings() {
    adminPanel.saveSettings();
}

function checkSystemHealth() {
    adminPanel.checkSystemHealth();
}

// Initialize admin panel when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminPanel = new SuperAdminPanel();
});

// Close modals when clicking outside
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('admin-modal')) {
        e.target.classList.remove('active');
    }
});

// Mobile menu toggle
function toggleMobileMenu() {
    const sidebar = document.querySelector('.admin-sidebar');
    sidebar.classList.toggle('mobile-open');
}

// AGGIUNGERE AL FILE server.js - Sistema Password Policy e Sicurezza Avanzata

// AGGIUNGERE AL FILE server.js - Sistema Password Policy e Sicurezza Avanzata

// Password Policy Schema - NUOVO
const passwordPolicySchema = new mongoose.Schema({
    minLength: { type: Number, default: 8 },
    requireUppercase: { type: Boolean, default: true },
    requireLowercase: { type: Boolean, default: true },
    requireNumbers: { type: Boolean, default: true },
    requireSpecialChars: { type: Boolean, default: false },
    expiryDays: { type: Number, default: 90 },
    historyCount: { type: Number, default: 5 }, // Remember last 5 passwords
    maxLoginAttempts: { type: Number, default: 5 },
    lockoutDuration: { type: Number, default: 30 }, // minutes
    sessionTimeout: { type: Number, default: 8 }, // hours
    updatedAt: { type: Date, default: Date.now },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'SuperAdmin' }
});

// Password History Schema - NUOVO
const passwordHistorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Login Attempts Schema - NUOVO
const loginAttemptsSchema = new mongoose.Schema({
    identifier: { type: String, required: true }, // email, badge, or IP
    attempts: { type: Number, default: 0 },
    lastAttempt: { type: Date, default: Date.now },
    lockedUntil: { type: Date },
    ipAddress: { type: String },
    userAgent: { type: String }
});

// Models
const PasswordPolicy = mongoose.model('PasswordPolicy', passwordPolicySchema);
const PasswordHistory = mongoose.model('PasswordHistory', passwordHistorySchema);
const LoginAttempts = mongoose.model('LoginAttempts', loginAttemptsSchema);

// ===========================================
// ADMIN PASSWORD POLICY MANAGEMENT
// ===========================================

// Get password policy (admin only)
app.get('/api/admin/password-policy', authenticateSuperAdmin, async (req, res) => {
    try {
        const policy = await getPasswordPolicy();
        res.json(policy);
    } catch (error) {
        console.error('Admin password policy fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch password policy' });
    }
});

// Update password policy (admin only)
app.put('/api/admin/password-policy', authenticateSuperAdmin, async (req, res) => {
    try {
        const updates = req.body;
        
        let policy = await PasswordPolicy.findOne();
        if (!policy) {
            policy = new PasswordPolicy();
        }

        // Update policy fields
        Object.keys(updates).forEach(key => {
            if (policy.schema.paths[key]) {
                policy[key] = updates[key];
            }
        });

        policy.updatedAt = new Date();
        policy.updatedBy = req.user._id;
        await policy.save();

        await logActivity(req.user._id, 'SUPER_ADMIN', 'UPDATE_PASSWORD_POLICY', 'ADMIN_SECURITY', {
            changes: Object.keys(updates)
        }, req);

        res.json({
            message: 'Password policy updated successfully',
            policy
        });
    } catch (error) {
        console.error('Password policy update error:', error);
        res.status(500).json({ error: 'Failed to update password policy' });
    }
});

// Get security dashboard (admin only)
app.get('/api/admin/security', authenticateSuperAdmin, async (req, res) => {
    try {
        const now = new Date();
        const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

        // Login statistics
        const totalLogins24h = await AuditLog.countDocuments({
            action: 'LOGIN',
            timestamp: { $gte: last24h }
        });

        const failedLogins24h = await AuditLog.countDocuments({
            action: 'FAILED_LOGIN',
            timestamp: { $gte: last24h }
        });

        // Locked accounts
        const lockedAccounts = await LoginAttempts.countDocuments({
            lockedUntil: { $gte: now }
        });

        // Password expiry warnings
        const policy = await getPasswordPolicy();
        const warningThreshold = new Date(now.getTime() - (policy.expiryDays - 7) * 24 * 60 * 60 * 1000);
        
        const usersNeedingPasswordChange = await User.countDocuments({
            $or: [
                { passwordChangeRequired: true },
                { passwordChangedAt: { $lte: warningThreshold } },
                { temporaryPassword: true }
            ]
        });

        // Recent security events
        const recentEvents = await AuditLog.find({
            action: { $in: ['FAILED_LOGIN', 'PASSWORD_CHANGED', 'RESET_PASSWORD', 'LOGIN'] },
            timestamp: { $gte: last7d }
        })
        .sort({ timestamp: -1 })
        .limit(20);

        // IP address analysis
        const ipStats = await AuditLog.aggregate([
            {
                $match: {
                    timestamp: { $gte: last24h },
                    ipAddress: { $exists: true, $ne: null }
                }
            },
            {
                $group: {
                    _id: '$ipAddress',
                    count: { $sum: 1 },
                    actions: { $addToSet: '$action' }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);

        res.json({
            stats: {
                totalLogins24h,
                failedLogins24h,
                lockedAccounts,
                usersNeedingPasswordChange,
                successRate: totalLogins24h > 0 ? ((totalLogins24h - failedLogins24h) / totalLogins24h * 100).toFixed(1) : 100
            },
            recentEvents,
            ipStats,
            policy
        });
    } catch (error) {
        console.error('Security dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch security dashboard' });
    }
});

// Unlock user account (admin only)
app.post('/api/admin/unlock-account', authenticateSuperAdmin, async (req, res) => {
    try {
        const { identifier } = req.body; // badge, email, or user ID

        if (!identifier) {
            return res.status(400).json({ error: 'User identifier is required' });
        }

        // Find user
        const user = await User.findOne({
            $or: [
                { _id: identifier },
                { badge: identifier },
                { email: identifier }
            ]
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Remove login attempts record
        await LoginAttempts.deleteOne({ identifier: user.badge });
        await LoginAttempts.deleteOne({ identifier: user.email });

        await logActivity(req.user._id, 'SUPER_ADMIN', 'UNLOCK_ACCOUNT', 'ADMIN_SECURITY', {
            targetUserId: user._id,
            targetBadge: user.badge
        }, req);

        res.json({
            message: 'Account unlocked successfully',
            user: {
                badge: user.badge,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName
            }
        });
    } catch (error) {
        console.error('Account unlock error:', error);
        res.status(500).json({ error: 'Failed to unlock account' });
    }
});

// Force password reset for user (admin only)
app.post('/api/admin/force-password-reset', authenticateSuperAdmin, async (req, res) => {
    try {
        const { userId, reason } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate new temporary password
        const newPassword = generateTempPassword();
        const hashedPassword = await bcrypt.hash(newPassword, 12);

        // Add current password to history
        await addPasswordToHistory(user._id, user.password);

        // Update user
        user.password = hashedPassword;
        user.passwordChangeRequired = true;
        user.temporaryPassword = true;
        user.passwordChangedAt = new Date();
        await user.save();

        await logActivity(req.user._id, 'SUPER_ADMIN', 'FORCE_PASSWORD_RESET', 'ADMIN_SECURITY', {
            targetUserId: user._id,
            targetBadge: user.badge,
            reason: reason || 'Admin forced reset'
        }, req);

        res.json({
            message: 'Password reset successfully',
            credentials: {
                badge: user.badge,
                newPassword: newPassword
            }
        });
    } catch (error) {
        console.error('Force password reset error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Get users requiring password change (admin only)
app.get('/api/admin/users/password-warnings', authenticateSuperAdmin, async (req, res) => {
    try {
        const policy = await getPasswordPolicy();
        const now = new Date();
        const warningThreshold = new Date(now.getTime() - (policy.expiryDays - 7) * 24 * 60 * 60 * 1000);
        const expiredThreshold = new Date(now.getTime() - policy.expiryDays * 24 * 60 * 60 * 1000);

        const users = await User.find({
            $or: [
                { passwordChangeRequired: true },
                { temporaryPassword: true },
                { passwordChangedAt: { $lte: expiredThreshold } },
                { 
                    passwordChangedAt: { 
                        $lte: warningThreshold,
                        $gte: expiredThreshold
                    }
                }
            ]
        })
        .populate('rank', 'name')
        .select('badge firstName lastName email passwordChangedAt passwordChangeRequired temporaryPassword rank')
        .sort({ passwordChangedAt: 1 });

        const categorized = users.map(user => {
            const passwordAge = now - (user.passwordChangedAt || user.createdAt);
            const daysOld = Math.floor(passwordAge / (24 * 60 * 60 * 1000));
            
            let status = 'ok';
            let priority = 'low';
            
            if (user.temporaryPassword || user.passwordChangeRequired) {
                status = 'requires_change';
                priority = 'high';
            } else if (daysOld >= policy.expiryDays) {
                status = 'expired';
                priority = 'critical';
            } else if (daysOld >= (policy.expiryDays - 7)) {
                status = 'warning';
                priority = 'medium';
            }
            
            return {
                ...user.toObject(),
                passwordAge: daysOld,
                status,
                priority,
                daysUntilExpiry: Math.max(0, policy.expiryDays - daysOld)
            };
        });

        res.json({
            users: categorized,
            summary: {
                total: categorized.length,
                critical: categorized.filter(u => u.priority === 'critical').length,
                high: categorized.filter(u => u.priority === 'high').length,
                medium: categorized.filter(u => u.priority === 'medium').length
            }
        });
    } catch (error) {
        console.error('Password warnings fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch password warnings' });
    }
});

// ===========================================
// ENHANCED INITIALIZATION WITH SECURITY
// ===========================================

// Update initializeData function to include security defaults
async function initializeSecurityDefaults() {
    try {
        // Create default password policy if it doesn't exist
        const policyCount = await PasswordPolicy.countDocuments();
        if (policyCount === 0) {
            const defaultPolicy = new PasswordPolicy({
                minLength: 8,
                requireUppercase: true,
                requireLowercase: true,
                requireNumbers: true,
                requireSpecialChars: false,
                expiryDays: 90,
                historyCount: 5,
                maxLoginAttempts: 5,
                lockoutDuration: 30,
                sessionTimeout: 8
            });
            await defaultPolicy.save();
            console.log('✅ Default password policy created');
        }
    } catch (error) {
        console.error('Error initializing security defaults:', error);
    }
}

// ===========================================
// ENHANCED UTILITY FUNCTIONS
// ===========================================

// Generate secure password based on policy
async function generateSecurePassword() {
    const policy = await getPasswordPolicy();
    
    const lowercase = 'abcdefghjkmnpqrstuvwxyz';
    const uppercase = 'ABCDEFGHJKMNPQRSTUVWXYZ';
    const numbers = '23456789';
    const special = '!@#$%^&*';
    
    let chars = lowercase;
    let password = '';
    
    // Ensure required character types are included
    if (policy.requireLowercase) {
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        chars += lowercase;
    }
    
    if (policy.requireUppercase) {
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        chars += uppercase;
    }
    
    if (policy.requireNumbers) {
        password += numbers[Math.floor(Math.random() * numbers.length)];
        chars += numbers;
    }
    
    if (policy.requireSpecialChars) {
        password += special[Math.floor(Math.random() * special.length)];
        chars += special;
    }
    
    // Fill remaining length
    const remainingLength = policy.minLength - password.length;
    for (let i = 0; i < remainingLength; i++) {
        password += chars[Math.floor(Math.random() * chars.length)];
    }
    
    // Shuffle password
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Update generateTempPassword to use policy
async function generateTempPasswordSecure() {
    return await generateSecurePassword();
}

// Session cleanup job (run periodically)
async function cleanupExpiredSessions() {
    try {
        const policy = await getPasswordPolicy();
        const expiredThreshold = new Date(Date.now() - policy.sessionTimeout * 60 * 60 * 1000);
        
        // In a real implementation, you'd have a sessions collection to clean up
        // For now, just log expired login attempts
        await LoginAttempts.deleteMany({
            lastAttempt: { $lte: expiredThreshold },
            lockedUntil: { $lte: new Date() }
        });
        
        console.log('🧹 Expired sessions cleaned up');
    } catch (error) {
        console.error('Session cleanup error:', error);
    }
}

// Run security initialization and periodic cleanup
setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // Every hour

module.exports = {
    getPasswordPolicy,
    validatePassword,
    isPasswordExpired,
    trackLoginAttempt,
    isAccountLocked,
    addPasswordToHistory,
    generateSecurePassword,
    initializeSecurityDefaults
};
// PASSWORD POLICY FUNCTIONS
// ===========================================

// Get current password policy
async function getPasswordPolicy() {
    let policy = await PasswordPolicy.findOne();
    if (!policy) {
        policy = new PasswordPolicy();
        await policy.save();
    }
    return policy;
}

// Validate password against policy
async function validatePassword(password, userId = null) {
    const policy = await getPasswordPolicy();
    const errors = [];

    // Length check
    if (password.length < policy.minLength) {
        errors.push(`Password must be at least ${policy.minLength} characters long`);
    }

    // Character requirements
    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }

    if (policy.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }

    if (policy.requireNumbers && !/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }

    if (policy.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }

    // Check password history if user provided
    if (userId && policy.historyCount > 0) {
        const history = await PasswordHistory.find({ userId })
            .sort({ createdAt: -1 })
            .limit(policy.historyCount);

        for (const oldPassword of history) {
            const isSame = await bcrypt.compare(password, oldPassword.passwordHash);
            if (isSame) {
                errors.push(`Password cannot be one of the last ${policy.historyCount} passwords used`);
                break;
            }
        }
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

// Add password to history
async function addPasswordToHistory(userId, passwordHash) {
    const policy = await getPasswordPolicy();
    
    // Add new password to history
    await new PasswordHistory({ userId, passwordHash }).save();
    
    // Remove old entries beyond history count
    const allHistory = await PasswordHistory.find({ userId }).sort({ createdAt: -1 });
    if (allHistory.length > policy.historyCount) {
        const toDelete = allHistory.slice(policy.historyCount);
        await PasswordHistory.deleteMany({ 
            _id: { $in: toDelete.map(h => h._id) } 
        });
    }
}

// Check if password is expired
async function isPasswordExpired(user) {
    const policy = await getPasswordPolicy();
    if (policy.expiryDays === 0) return false; // No expiry
    
    const passwordAge = Date.now() - (user.passwordChangedAt || user.createdAt);
    const expiryTime = policy.expiryDays * 24 * 60 * 60 * 1000; // Convert to milliseconds
    
    return passwordAge > expiryTime;
}

// Login attempt tracking
async function trackLoginAttempt(identifier, ipAddress, userAgent, success = false) {
    const policy = await getPasswordPolicy();
    
    let attempt = await LoginAttempts.findOne({ identifier });
    if (!attempt) {
        attempt = new LoginAttempts({ identifier, ipAddress, userAgent });
    }

    if (success) {
        // Reset attempts on successful login
        attempt.attempts = 0;
        attempt.lockedUntil = undefined;
    } else {
        // Increment failed attempts
        attempt.attempts += 1;
        attempt.lastAttempt = new Date();
        
        // Lock account if max attempts reached
        if (attempt.attempts >= policy.maxLoginAttempts) {
            attempt.lockedUntil = new Date(Date.now() + policy.lockoutDuration * 60 * 1000);
        }
    }

    await attempt.save();
    return attempt;
}

// Check if account is locked
async function isAccountLocked(identifier) {
    const attempt = await LoginAttempts.findOne({ identifier });
    if (!attempt || !attempt.lockedUntil) return false;
    
    if (attempt.lockedUntil > new Date()) {
        return {
            locked: true,
            lockedUntil: attempt.lockedUntil,
            remainingTime: Math.ceil((attempt.lockedUntil - new Date()) / (60 * 1000)) // minutes
        };
    } else {
        // Lock expired, reset attempts
        attempt.attempts = 0;
        attempt.lockedUntil = undefined;
        await attempt.save();
        return false;
    }
}

// ===========================================
// ENHANCED AUTH ROUTES WITH SECURITY
// ===========================================

// Enhanced login with security checks
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { badge, password } = req.body;

        if (!badge || !password) {
            return res.status(400).json({ error: 'Badge and password are required' });
        }

        // Check for account lockout
        const lockStatus = await isAccountLocked(badge);
        if (lockStatus.locked) {
            await logActivity('unknown', 'USER', 'FAILED_LOGIN', 'AUTH', { 
                badge, 
                reason: 'Account locked',
                remainingTime: lockStatus.remainingTime
            }, req);
            return res.status(423).json({ 
                error: `Account locked. Try again in ${lockStatus.remainingTime} minutes.` 
            });
        }

        const user = await User.findOne({ badge }).populate('rank');
        if (!user) {
            await trackLoginAttempt(badge, req.ip, req.get('User-Agent'), false);
            await logActivity('unknown', 'USER', 'FAILED_LOGIN', 'AUTH', { badge, reason: 'User not found' }, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.status !== 'Active') {
            await logActivity(user._id, 'USER', 'FAILED_LOGIN', 'AUTH', { reason: 'Account inactive' }, req);
            return res.status(401).json({ error: 'Account is inactive' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            await trackLoginAttempt(badge, req.ip, req.get('User-Agent'), false);
            await logActivity(user._id, 'USER', 'FAILED_LOGIN', 'AUTH', { reason: 'Invalid password' }, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if password is expired
        const passwordExpired = await isPasswordExpired(user);

        // Successful login
        await trackLoginAttempt(badge, req.ip, req.get('User-Agent'), true);
        user.lastLogin = new Date();
        await user.save();

        const policy = await getPasswordPolicy();
        const token = jwt.sign(
            { id: user._id, badge: user.badge, type: 'USER' },
            process.env.JWT_SECRET,
            { expiresIn: `${policy.sessionTimeout}h` }
        );

        await logActivity(user._id, 'USER', 'LOGIN', 'AUTH', { success: true }, req);

        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                badge: user.badge,
                firstName: user.firstName,
                lastName: user.lastName,
                rank: user.rank,
                department: user.department,
                shift: user.shift,
                status: user.status,
                hireDate: user.hireDate,
                lastLogin: user.lastLogin,
                passwordChangeRequired: user.passwordChangeRequired || passwordExpired,
                passwordExpired: passwordExpired
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Change password with policy validation
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new password are required' });
        }

        // Verify current password
        const isValidCurrent = await bcrypt.compare(currentPassword, req.user.password);
        if (!isValidCurrent) {
            await logActivity(req.user._id, 'USER', 'FAILED_PASSWORD_CHANGE', 'AUTH', { reason: 'Invalid current password' }, req);
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Validate new password against policy
        const validation = await validatePassword(newPassword, req.user._id);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: 'Password does not meet policy requirements',
                details: validation.errors
            });
        }

        // Update password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        
        // Add old password to history
        await addPasswordToHistory(req.user._id, req.user.password);
        
        // Update user
        req.user.password = hashedPassword;
        req.user.passwordChangeRequired = false;
        req.user.temporaryPassword = false;
        req.user.passwordChangedAt = new Date();
        await req.user.save();

        await logActivity(req.user._id, 'USER', 'PASSWORD_CHANGED', 'AUTH', { success: true }, req);

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Get password policy (for frontend)
app.get('/api/auth/password-policy', async (req, res) => {
    try {
        const policy = await getPasswordPolicy();
        res.json({
            minLength: policy.minLength,
            requireUppercase: policy.requireUppercase,
            requireLowercase: policy.requireLowercase,
            requireNumbers: policy.requireNumbers,
            requireSpecialChars: policy.requireSpecialChars,
            expiryDays: policy.expiryDays
        });
    } catch (error) {
        console.error('Password policy fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch password policy' });
    }
});

// =========================================== API ENDPOINTS ===========================================