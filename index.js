const express = require('express');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');

const app = express();

// In-memory database (replace with real database in production)
const users = {};

// Middleware
app.use(compression({
    level: 5,
    threshold: 0,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    headers: true
});
app.use(limiter);

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept'
    );
    console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url}`);
    next();
});

// Login Endpoint
app.post('/player/growid/login/validate', async (req, res) => {
    try {
        const { growId, password } = req.body;

        // Validate input
        if (!growId || !password) {
            return res.status(400).json({
                status: "error",
                message: "GrowID and password are required"
            });
        }

        // Check if user exists
        if (!users[growId.toLowerCase()]) {
            return res.status(401).json({
                status: "error",
                message: "Invalid credentials"
            });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, users[growId.toLowerCase()].password);
        if (!isMatch) {
            return res.status(401).json({
                status: "error",
                message: "Invalid credentials"
            });
        }

        // Create token
        const token = Buffer.from(
            `_token=${uuidv4()}&growId=${growId}&timestamp=${Date.now()}`
        ).toString('base64');

        res.json({
            status: "success",
            message: "Login successful",
            token: token,
            accountType: "growtopia",
            user: {
                growId: growId,
                email: users[growId.toLowerCase()].email
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            status: "error",
            message: "Internal server error"
        });
    }
});

// Registration Endpoint
app.post('/player/growid/register/validate', async (req, res) => {
    try {
        const { growId, password, verifyPassword, email } = req.body;

        // Validate input
        if (!growId || !password || !verifyPassword || !email) {
            return res.status(400).json({
                status: "error",
                message: "All fields are required"
            });
        }

        if (growId.length < 8) {
            return res.status(400).json({
                status: "error",
                message: "GrowID must be at least 8 characters"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                status: "error",
                message: "Password must be at least 8 characters"
            });
        }

        if (password !== verifyPassword) {
            return res.status(400).json({
                status: "error",
                message: "Passwords do not match"
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({
                status: "error",
                message: "Invalid email address"
            });
        }

        // Check if user already exists
        if (users[growId.toLowerCase()]) {
            return res.status(400).json({
                status: "error",
                message: "GrowID already exists"
            });
        }

        // Check if email is already used
        const emailExists = Object.values(users).some(user => user.email === email);
        if (emailExists) {
            return res.status(400).json({
                status: "error",
                message: "Email already registered"
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create new user
        users[growId.toLowerCase()] = {
            growId: growId,
            email: email,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };

        // Create token
        const token = Buffer.from(
            `_token=${uuidv4()}&growId=${growId}&timestamp=${Date.now()}`
        ).toString('base64');

        res.status(201).json({
            status: "success",
            message: "Registration successful",
            token: token,
            accountType: "growtopia",
            user: {
                growId: growId,
                email: email
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            status: "error",
            message: "Internal server error"
        });
    }
});

// Other endpoints
app.all('/player/*', (req, res) => {
    res.status(301).redirect('https://api.yoruakio.tech/player/' + req.path.slice(8));
});

app.get('/', (req, res) => {
    res.send('Growtopia API Server');
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
