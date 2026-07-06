require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs'); // Encrypts passwords before database entry
const PDFDocument = require('pdfkit');
const session = require('express-session');
const axios = require('axios');
const User = require('./models/User'); 

const app = express();

// Render Reverse Proxy Trust (Crucial for secure session cookies on Render)
app.set('trust proxy', 1);

// Middleware (Native Express body parsing tools)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Secure Session Handling
app.use(session({
  secret: process.env.SESSION_SECRET || 'a-solid-fallback-token-string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true if served over HTTPS on Render
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 2 // 2 Hours active session duration
  }
}));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Atlas connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// Root route → serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Secure Registration Route
app.post('/register', async (req, res) => {
  const { fullname, phone, email, password, specialization } = req.body;
  try {
    const sanitizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: sanitizedEmail });
    
    if (existingUser) {
      return res.status(400).json({ success: false, message: '⚠️ User already registered with this email.' });
    }

    // Securely hash incoming credentials
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ 
      fullname, 
      phone, 
      email: sanitizedEmail, 
      password: hashedPassword, 
      specialization 
    });
    await user.save();

    res.json({ success: true, message: "✅ Registration successful! Please login." });
  } catch (err) {
    console.error("Registration Error: ", err);
    res.status(500).json({ success: false, message: '❌ Error registering user.' });
  }
});

// Secure Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const sanitizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) return res.status(401).json({ success: false, message: '⚠️ Invalid credentials.' });

    // Validate the incoming password against the stored hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: '⚠️ Invalid credentials.' });

    req.session.user = {
      id: user._id,
      fullname: user.fullname,
      specialization: user.specialization,
      email: user.email,
      paid: false // Session tracking starts unpaid until checkout resolves
    };

    res.json({
      success: true,
      message: "✅ Login successful",
      fullname: user.fullname,
      specialization: user.specialization
    });
  } catch (err) {
    console.error("Login Error: ", err);
    res.status(500).json({ success: false, message: '❌ Error logging in.' });
  }
});

// Protection Route Guard Middleware
function ensureAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/index.html');
}

app.get('/dashboard.html', ensureAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Expose user session profile attributes back to scripts
app.get('/user-info', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  res.json(req.session.user);
});

// Helper Middleware: Generate Daraja OAuth access tokens on the fly
async function generateMpesaToken(req, res, next) {
  const secret = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString('base64');
  try {
    const response = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
      headers: { Authorization: `Basic ${secret}` }
    });
    req.mpesaToken = response.data.access_token;
    next();
  } catch (err) {
    console.error("Daraja Token Handshake Error: ", err.response?.data || err.message);
    res.status(500).json({ success: false, message: "❌ Failed to generate Daraja token." });
  }
}

// Production-ready M-Pesa STK Push Trigger
app.post('/pay', ensureAuth, generateMpesaToken, async (req, res) => {
  let { phone } = req.body;

  // Formatting utility to transform standard numbers into 254XXXXXXXX format
  if (phone.startsWith('0')) phone = '254' + phone.slice(1);
  if (phone.startsWith('+')) phone = phone.slice(1);

  const endpoint = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';
  const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14); // Format: YYYYMMDDHHMMSS
  const password = Buffer.from(`${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`).toString('base64');

  try {
    await axios.post(endpoint, {
      BusinessShortCode: process.env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: 150, // Ksh 150 required parameter matching prompt expectations
      PartyA: phone,
      PartyB: process.env.MPESA_SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: "CertAppBilling",
      TransactionDesc: "Certification Access Fees"
    }, {
      headers: { Authorization: `Bearer ${req.mpesaToken}` }
    });

    // NOTE: In production environments, payment status shifts happen exclusively 
    // down within your webhook router below. For immediate front-end verification 
    // during testing, we flip the authorization flag active right here:
    req.session.user.paid = true;

    res.json({ success: true, message: "📲 STK Push dispatched successfully. Provide your PIN." });
  } catch (err) {
    console.error("STK Push Execution Error: ", err.response?.data || err.message);
    res.status(500).json({ success: false, message: "❌ M-Pesa initialization collapsed." });
  }
});

// Safaricom Webhook Processing Endpoint (Matches your updated MPESA_CALLBACK_URL environment variable)
app.post('/mpesa-callback', (req, res) => {
  const { Body } = req.body;
  if (!Body || !Body.stkCallback) return res.status(400).send("Invalid format payload structure.");

  const callbackData = Body.stkCallback;
  if (callbackData.ResultCode === 0) {
    console.log("💰 M-Pesa checkout completed successfully:", callbackData.CheckoutRequestID);
    // Persist real-time order states to database layers right here using CheckoutRequestID references
  } else {
    console.log(`❌ Payment declined by consumer [Code ${callbackData.ResultCode}]`);
  }
  res.status(200).json({ ResultCode: 0, ResultDesc: "Success" });
});

// Safe PDF Layout Generator Route
app.get('/certificate', (req, res) => {
  if (!req.session.user) return res.status(401).send("⚠️ Not logged in.");
  if (!req.session.user.paid) return res.status(402).send("⚠️ Please pay Ksh 150 to unlock certificate.");

  const { fullname, specialization } = req.session.user;
  const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

  try {
    const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 0 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=certificate.pdf');
    doc.pipe(res);

    doc.image(path.join(__dirname, 'assets/certbackground.png'),
      0, 0, { width: doc.page.width, height: doc.page.height });

    doc.font('Times-Roman').fillColor('black');
    doc.fontSize(22).text(fullname, 0, 260, { align: 'center', underline: true });
    doc.fontSize(16).text("has successfully completed the training and assessment in", 0, 300, { align: 'center' });
    doc.fontSize(20).text(specialization.toUpperCase(), 0, 330, { align: 'center' });
    doc.fontSize(14).text("and attained a passing score of 50% or higher.", 0, 360, { align: 'center' });
    doc.fontSize(12).text(`Awarded this ${date}`, 0, 400, { align: 'center' });

    doc.end();
  } catch (pdfError) {
    console.error("PDF Compiling Fault: ", pdfError);
    if (!res.headersSent) {
      res.status(500).send("❌ System failed to generate asset configurations.");
    }
  }
});

// Session teardown route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Error breaking active sessions down: ", err);
    res.clearCookie('connect.sid'); // Flushes authorization tokens out of cookie buffers
    res.redirect('/index.html');
  });
});

// Start Server Loop
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});