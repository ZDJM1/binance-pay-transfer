
// Binance Pay Transfer System - Node.js + Express + MongoDB

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecretkey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Binance API Credentials
const API_KEY = process.env.BINANCE_API_KEY;
const API_SECRET = process.env.BINANCE_API_SECRET;

// Generate Binance Pay Signature
function generateSignature(payload) {
    return crypto.createHmac('sha512', API_SECRET)
                 .update(JSON.stringify(payload))
                 .digest('hex');
}

// Serve Home Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = user;
            return res.json({ success: true, message: 'Login successful' });
        }
        res.status(401).json({ error: 'Invalid credentials' });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Transfer Funds using Binance Pay
app.post('/transfer', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const { amount, currency, recipientUid } = req.body;
        
        if (!amount || !currency || !recipientUid) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const payload = {
            merchantTradeNo: `TRANS_${Date.now()}`,
            currency,
            amount,
            recipientUid
        };

        const signature = generateSignature(payload);
        
        const response = await axios.post('https://bpay.binanceapi.com/binancepay/openapi/v2/order', payload, {
            headers: {
                'Content-Type': 'application/json',
                'BinancePay-Timestamp': Date.now(),
                'BinancePay-Nonce': crypto.randomBytes(16).toString('hex'),
                'BinancePay-Signature': signature,
                'BinancePay-Certificate-SN': API_KEY
            }
        });
        
        res.json({ success: true, data: response.data });
    } catch (error) {
        res.status(500).json({ error: 'Transaction failed' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
    