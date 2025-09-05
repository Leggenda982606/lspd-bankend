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
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: { error: 'Too many login attempts, please try again later.' },
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

// Rank Schema
const rankSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    level: { type: Number, required: true, unique: true },
    canManage: [{ type: Number }], // Array of rank levels this rank can manage
    permissions: {
        viewReports: { type: Boolean, default: true },
        createReports: { type: Boolean, default: true },
        managePersonnel: { type: Boolean, default: false },
        adminPanel: { type: Boolean, default: false },
        manageRanks: { type: Boolean, default: false },
        viewDisciplinary: { type: Boolean, default: false },
        issueDisciplinary: { type: Boolean, default: false }
    },
    createdAt: { type: Date, default: Date.now }
});

// User Schema
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
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

// Report Schema
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

// Disciplinary Schema
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

// Rules Schema
const ruleSchema = new mongoose.Schema({
    section: { type: String, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    order: { type: Number, required: true },
    lastUpdated: { type: Date, default: Date.now },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

// Models
const User = mongoose.model('User', userSchema);
const Rank = mongoose.model('Rank', rankSchema);
const Report = mongoose.model('Report', reportSchema);
const Disciplinary = mongoose.model('Disciplinary', disciplinarySchema);
const Rule = mongoose.model('Rule', ruleSchema);

// Auth Middleware
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
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Permission Check Middleware
const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.user.rank.permissions[permission]) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// Initialize Default Data
async function initializeData() {
    try {
        // Create default ranks if they don't exist
        const rankCount = await Rank.countDocuments();
        if (rankCount === 0) {
            const defaultRanks = [
                {
                    name: 'Cadet',
                    level: 1,
                    canManage: [],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: false,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: false,
                        issueDisciplinary: false
                    }
                },
                {
                    name: 'Officer',
                    level: 2,
                    canManage: [1],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: false,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: false,
                        issueDisciplinary: false
                    }
                },
                {
                    name: 'Corporal',
                    level: 3,
                    canManage: [1, 2],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: true,
                        issueDisciplinary: false
                    }
                },
                {
                    name: 'Sergeant',
                    level: 4,
                    canManage: [1, 2, 3],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: false,
                        manageRanks: false,
                        viewDisciplinary: true,
                        issueDisciplinary: true
                    }
                },
                {
                    name: 'Lieutenant',
                    level: 5,
                    canManage: [1, 2, 3, 4],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: false,
                        viewDisciplinary: true,
                        issueDisciplinary: true
                    }
                },
                {
                    name: 'Captain',
                    level: 6,
                    canManage: [1, 2, 3, 4, 5],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: true,
                        viewDisciplinary: true,
                        issueDisciplinary: true
                    }
                },
                {
                    name: 'Chief',
                    level: 7,
                    canManage: [1, 2, 3, 4, 5, 6],
                    permissions: {
                        viewReports: true,
                        createReports: true,
                        managePersonnel: true,
                        adminPanel: true,
                        manageRanks: true,
                        viewDisciplinary: true,
                        issueDisciplinary: true
                    }
                }
            ];

            await Rank.insertMany(defaultRanks);
            console.log('✅ Default ranks created');
        }

        // Create default admin user
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            const chiefRank = await Rank.findOne({ name: 'Chief' });
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const badge = `LS-${Math.floor(1000 + Math.random() * 9000)}`;
            
            const adminUser = new User({
                email: 'admin@lspd.gov',
                badge: badge,
                password: hashedPassword,
                firstName: 'Admin',
                lastName: 'Chief',
                rank: chiefRank._id,
                department: 'Administration',
                shift: 'All'
            });

            await adminUser.save();
            console.log(`🔑 Default admin created! Badge: ${badge}`);
        }

        // Create default rules
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
                }
            ];

            await Rule.insertMany(defaultRules);
            console.log('✅ Default rules created');
        }

    } catch (error) {
        console.error('Error initializing data:', error);
    }
}

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'LSPD Backend is running!' });
});

// AUTH ROUTES
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { badge, password } = req.body;

        if (!badge || !password) {
            return res.status(400).json({ error: 'Badge and password are required' });
        }

        const user = await User.findOne({ badge }).populate('rank');
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.status !== 'Active') {
            return res.status(401).json({ error: 'Account is inactive' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        const token = jwt.sign(
            { id: user._id, badge: user.badge },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

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
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DASHBOARD ROUTES
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const totalOfficers = await User.countDocuments({ status: 'Active' });
        const totalReports = await Report.countDocuments();
        const pendingReports = await Report.countDocuments({ status: { $in: ['Draft', 'Submitted'] } });
        const activeCases = await Disciplinary.countDocuments({ status: 'Active' });

        const recentReports = await Report.find()
            .populate('officerInCharge', 'firstName lastName badge')
            .sort({ createdAt: -1 })
            .limit(5);

        const recentActivity = await User.find({ lastLogin: { $exists: true } })
            .populate('rank', 'name')
            .sort({ lastLogin: -1 })
            .limit(5);

        res.json({
            stats: {
                totalOfficers,
                totalReports,
                pendingReports,
                activeCases
            },
            recentReports,
            recentActivity
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// PERSONNEL ROUTES
app.get('/api/personnel', authenticateToken, requirePermission('managePersonnel'), async (req, res) => {
    try {
        const personnel = await User.find()
            .populate('rank', 'name level')
            .populate('createdBy', 'firstName lastName badge')
            .sort({ 'rank.level': -1, lastName: 1 });

        res.json(personnel);
    } catch (error) {
        console.error('Personnel fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch personnel' });
    }
});

app.post('/api/personnel', authenticateToken, requirePermission('managePersonnel'), async (req, res) => {
    try {
        const { email, firstName, lastName, rankId, department, shift } = req.body;

        // Validate rank permission
        const targetRank = await Rank.findById(rankId);
        if (!targetRank) {
            return res.status(400).json({ error: 'Invalid rank' });
        }

        if (!req.user.rank.canManage.includes(targetRank.level) && req.user.rank.level < targetRank.level) {
            return res.status(403).json({ error: 'Cannot assign this rank' });
        }

        const badge = `LS-${Math.floor(1000 + Math.random() * 9000)}`;
        const hashedPassword = await bcrypt.hash('temp123', 10);

        const newUser = new User({
            email,
            badge,
            password: hashedPassword,
            firstName,
            lastName,
            rank: rankId,
            department,
            shift,
            createdBy: req.user._id
        });

        await newUser.save();
        await newUser.populate('rank', 'name level');

        res.status(201).json({
            message: 'Officer created successfully',
            user: newUser,
            temporaryPassword: 'temp123'
        });
    } catch (error) {
        console.error('Personnel creation error:', error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: 'Failed to create officer' });
        }
    }
});

// RANKS ROUTES
app.get('/api/ranks', authenticateToken, async (req, res) => {
    try {
        const ranks = await Rank.find().sort({ level: 1 });
        res.json(ranks);
    } catch (error) {
        console.error('Ranks fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch ranks' });
    }
});

app.post('/api/ranks', authenticateToken, requirePermission('manageRanks'), async (req, res) => {
    try {
        const { name, level, canManage, permissions } = req.body;
        
        const newRank = new Rank({
            name,
            level,
            canManage,
            permissions
        });

        await newRank.save();
        res.status(201).json(newRank);
    } catch (error) {
        console.error('Rank creation error:', error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Rank name or level already exists' });
        } else {
            res.status(500).json({ error: 'Failed to create rank' });
        }
    }
});

// REPORTS ROUTES
app.get('/api/reports', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10, status, type } = req.query;
        const query = {};
        
        if (status) query.status = status;
        if (type) query.type = type;

        const reports = await Report.find(query)
            .populate('officerInCharge', 'firstName lastName badge')
            .populate('supervisingOfficer', 'firstName lastName badge')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Report.countDocuments(query);

        res.json({
            reports,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('Reports fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

app.post('/api/reports', authenticateToken, async (req, res) => {
    try {
        const { title, type, priority, description, location, date } = req.body;
        
        const reportNumber = `RPT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        
        const newReport = new Report({
            reportNumber,
            title,
            type,
            priority,
            description,
            location,
            date: new Date(date),
            officerInCharge: req.user._id
        });

        await newReport.save();
        await newReport.populate('officerInCharge', 'firstName lastName badge');

        res.status(201).json(newReport);
    } catch (error) {
        console.error('Report creation error:', error);
        res.status(500).json({ error: 'Failed to create report' });
    }
});

// DISCIPLINARY ROUTES
app.get('/api/disciplinary', authenticateToken, requirePermission('viewDisciplinary'), async (req, res) => {
    try {
        const { page = 1, limit = 10, status, type } = req.query;
        const query = {};
        
        if (status) query.status = status;
        if (type) query.type = type;

        const cases = await Disciplinary.find(query)
            .populate('officer', 'firstName lastName badge')
            .populate('issuedBy', 'firstName lastName badge')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Disciplinary.countDocuments(query);

        res.json({
            cases,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('Disciplinary fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch disciplinary cases' });
    }
});

app.post('/api/disciplinary', authenticateToken, requirePermission('issueDisciplinary'), async (req, res) => {
    try {
        const { officerId, type, reason, description, severity, expiryDate } = req.body;
        
        const caseNumber = `DSC-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        
        const newCase = new Disciplinary({
            caseNumber,
            officer: officerId,
            type,
            reason,
            description,
            severity,
            issuedBy: req.user._id,
            expiryDate: expiryDate ? new Date(expiryDate) : undefined
        });

        await newCase.save();
        await newCase.populate('officer', 'firstName lastName badge');
        await newCase.populate('issuedBy', 'firstName lastName badge');

        res.status(201).json(newCase);
    } catch (error) {
        console.error('Disciplinary creation error:', error);
        res.status(500).json({ error: 'Failed to create disciplinary case' });
    }
});

// RULES ROUTES
app.get('/api/rules', authenticateToken, async (req, res) => {
    try {
        const rules = await Rule.find()
            .populate('updatedBy', 'firstName lastName badge')
            .sort({ section: 1, order: 1 });

        res.json(rules);
    } catch (error) {
        console.error('Rules fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch rules' });
    }
});

app.post('/api/rules', authenticateToken, requirePermission('adminPanel'), async (req, res) => {
    try {
        const { section, title, content, order } = req.body;
        
        const newRule = new Rule({
            section,
            title,
            content,
            order,
            updatedBy: req.user._id
        });

        await newRule.save();
        await newRule.populate('updatedBy', 'firstName lastName badge');

        res.status(201).json(newRule);
    } catch (error) {
        console.error('Rule creation error:', error);
        res.status(500).json({ error: 'Failed to create rule' });
    }
});

app.put('/api/rules/:id', authenticateToken, requirePermission('adminPanel'), async (req, res) => {
    try {
        const { section, title, content, order } = req.body;
        
        const rule = await Rule.findByIdAndUpdate(
            req.params.id,
            {
                section,
                title,
                content,
                order,
                lastUpdated: new Date(),
                updatedBy: req.user._id
            },
            { new: true }
        ).populate('updatedBy', 'firstName lastName badge');

        if (!rule) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        res.json(rule);
    } catch (error) {
        console.error('Rule update error:', error);
        res.status(500).json({ error: 'Failed to update rule' });
    }
});

// Start server
app.listen(PORT, async () => {
    console.log(`🚀 LSPD Backend running on port ${PORT}`);
    await initializeData();
    console.log('Your service is live 🎉');
});

module.exports = app;
