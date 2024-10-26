const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const port = 3019;

const app = express();
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Middleware to parse JSON bodies

// Session management
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/student_info');

const db = mongoose.connection;

// Error and connection handlers
db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => {
    console.log("MongoDB connection successful");
});

// User schema and model
const userSchema = new mongoose.Schema({
    Name: String,
    email: { type: String, unique: true }, // Ensure email is unique
    password: String,
});

const Users = mongoose.model("User", userSchema);

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'landing.html'));
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// Registration route
app.post('/register', async (req, res) => {
    try {
        const { Name, email, password } = req.body;
        console.log('Received data:', { Name, email, password }); // Log the received data
        
        // Check if user already exists
        const existingUser = await Users.findOne({ email });
        if (existingUser) {
            return res.status(400).send('User with this email already exists.');
        }

        // Ensure password is not undefined
        if (!password) {
            return res.status(400).send('Password is required');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Hashed password:', hashedPassword); // Log the hashed password

        const user = new Users({ Name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// Login route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await Users.findOne({ email });
        
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = user; // Save user session
            res.redirect('/'); // Redirect to landing page upon successful login
        } else {
            res.status(401).send('Invalid email or password');
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send('Error logging in');
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

// Start server
app.listen(port, () => {
    console.log("Server started on port", port);
});