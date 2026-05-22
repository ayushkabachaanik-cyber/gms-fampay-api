const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const app = express();

app.use(cors());
app.use(express.static('public'));
app.use(express.json());

const DB_FILE = 'db.json';
const JWT_SECRET = process.env.JWT_SECRET || 'gms-fampay-secret-2025';

const orders = new Map();

function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  }
  return { users: {} };
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function generateApiKey() {
  return 'GMS' + Math.random().toString(36).substring(2, 9).toUpperCase() +
         Math.random().toString(36).substring(2, 9).toUpperCase();
}

function generateWebhookSecret() {
  return 'GMSWH_' + Math.random().toString(36).substring(2, 10).toUpperCase() +
         Math.random().toString(36).substring(2, 10).toUpperCase();
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.userId = payload.gmail;
    next();
  } catch (e) {
    return res.status(401).json({ status: 'error', message: 'Invalid token' });
  }
}

// ====================== SIGN UP ======================
// UPI VPA validator — rejects plain email domains, requires valid UPI handle
const INVALID_UPI_DOMAINS = ['gmail.com','yahoo.com','yahoo.in','hotmail.com','outlook.com','icloud.com','rediffmail.com','live.com'];
function validateUpiId(upi) {
  const clean = upi.toLowerCase().trim();
  if (!clean.includes('@') || clean.indexOf('@') !== clean.lastIndexOf('@')) return false;
  const [user, handle] = clean.split('@');
  if (!user || user.length < 1) return false;
  if (INVALID_UPI_DOMAINS.includes(handle)) return false;
  // Must be alphanumeric/dot/hyphen/underscore handle
  if (!/^[a-z0-9._\-]+$/.test(handle)) return false;
  return true;
}

app.post('/auth/signup', async (req, res) => {
  const { gmail, upi, password } = req.body;
  if (!gmail || !upi || !password) {
    return res.json({ status: 'error', message: 'All fields are required' });
  }
  const cleanPass = password.replace(/\s/g, '');
  if (cleanPass.length < 8) {
    return res.json({ status: 'error', message: 'Google App Password must be at least 8 characters (spaces are ignored)' });
  }
  if (!validateUpiId(upi)) {
    return res.json({ status: 'error', message: 'Invalid UPI ID. Use your real UPI VPA like name@upi, number@ybl, name@okicici — not your Gmail address.' });
  }

  const db = loadDB();
  const key = gmail.toLowerCase().trim();

  if (db.users[key]) {
    return res.json({ status: 'error', message: 'Account already exists. Please login.' });
  }

  const hashedPassword = await bcrypt.hash(cleanPass, 10);
  const apiKey = generateApiKey();
  const webhookSecret = generateWebhookSecret();

  db.users[key] = {
    gmail: key,
    upi: upi.toLowerCase().trim(),
    password: hashedPassword,
    apiKey,
    webhookSecret,
    createdAt: new Date().toISOString()
  };

  saveDB(db);

  const token = jwt.sign({ gmail: key }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    status: 'success',
    message: 'Account created successfully!',
    token,
    user: { gmail: key, upi: upi.toLowerCase().trim(), apiKey, webhookSecret }
  });
});

// ====================== LOGIN ======================
app.post('/auth/login', async (req, res) => {
  const { gmail, password } = req.body;
  if (!gmail || !password) {
    return res.json({ status: 'error', message: 'Email and Google App Password are required' });
  }

  const db = loadDB();
  const key = gmail.toLowerCase().trim();
  const user = db.users[key];

  if (!user) {
    return res.json({ status: 'error', message: 'No account found with this email' });
  }

  const cleanPass = password.replace(/\s/g, '');

  // Try stripped password first (new accounts), then original (legacy accounts hashed with spaces)
  let match = await bcrypt.compare(cleanPass, user.password);
  if (!match) {
    const legacyMatch = await bcrypt.compare(password, user.password);
    if (!legacyMatch) {
      return res.json({ status: 'error', message: 'Incorrect Google App Password' });
    }
    // Upgrade legacy account: re-hash without spaces so future logins work cleanly
    user.password = await bcrypt.hash(cleanPass, 10);
    saveDB(db);
  }

  // Auto-generate webhookSecret for legacy accounts that don't have one
  if (!user.webhookSecret) {
    user.webhookSecret = generateWebhookSecret();
    saveDB(db);
  }

  const token = jwt.sign({ gmail: key }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    status: 'success',
    message: 'Logged in successfully!',
    token,
    user: { gmail: user.gmail, upi: user.upi, apiKey: user.apiKey, webhookSecret: user.webhookSecret }
  });
});

// ====================== GET PROFILE ======================
app.get('/auth/me', authMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users[req.userId];
  if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });

  if (!user.webhookSecret) {
    user.webhookSecret = generateWebhookSecret();
    saveDB(db);
  }

  res.json({
    status: 'success',
    user: { gmail: user.gmail, upi: user.upi, apiKey: user.apiKey, webhookSecret: user.webhookSecret, createdAt: user.createdAt }
  });
});

// ====================== UPDATE UPI ID ======================
app.post('/auth/update-upi', authMiddleware, async (req, res) => {
  const { upi } = req.body;
  if (!upi) return res.json({ status: 'error', message: 'UPI ID is required' });
  if (!validateUpiId(upi)) {
    return res.json({ status: 'error', message: 'Invalid UPI ID. Use your real UPI VPA like name@upi, number@ybl, name@okicici — not your Gmail address.' });
  }
  const db = loadDB();
  const user = db.users[req.userId];
  if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
  db.users[req.userId].upi = upi.toLowerCase().trim();
  saveDB(db);
  res.json({ status: 'success', message: 'UPI ID updated!', upi: upi.toLowerCase().trim() });
});

// ====================== REVOKE & REGENERATE API ======================
app.post('/auth/revoke-api', authMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users[req.userId];
  if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });

  const newApiKey = generateApiKey();
  db.users[req.userId].apiKey = newApiKey;
  saveDB(db);

  res.json({ status: 'success', message: 'API key regenerated!', apiKey: newApiKey });
});

// ====================== PAYMENT WEBHOOK ======================
app.post('/webhook/payment', (req, res) => {
  const { order_id, webhook_secret, utr, amount, sender_name } = req.body;

  if (!order_id || !webhook_secret) {
    return res.status(400).json({ status: 'error', message: 'order_id and webhook_secret are required' });
  }

  const db = loadDB();
  const user = Object.values(db.users).find(u => u.webhookSecret === webhook_secret);

  if (!user) {
    return res.status(403).json({ status: 'error', message: 'Invalid webhook_secret' });
  }

  const order = orders.get(order_id);
  if (!order) {
    return res.status(404).json({ status: 'error', message: 'Order not found' });
  }

  const EXPIRY_MS = 5 * 60 * 1000;
  if ((Date.now() - order.createdAt) >= EXPIRY_MS) {
    return res.status(410).json({ status: 'error', message: 'Order has expired' });
  }

  if (order.paid) {
    return res.json({ status: 'success', message: 'Order was already marked as paid' });
  }

  order.paid = true;
  order.utr = utr || ('WH' + Math.floor(Math.random() * 1e10));
  order.amount = amount || order.amount;
  order.sender_name = sender_name || 'Unknown';
  order.transaction_id = 'FMPIB' + Math.floor(Math.random() * 1e9);
  order.payment_time_ist = new Date().toLocaleString('en-IN');

  res.json({
    status: 'success',
    message: 'Payment confirmed successfully',
    data: {
      order_id,
      transaction_id: order.transaction_id,
      utr: order.utr,
      amount: order.amount,
      sender_name: order.sender_name,
      payment_time_ist: order.payment_time_ist
    }
  });
});

// ====================== GENERATE QR ======================
app.get('/api/qr', (req, res) => {
  const apiKey = req.query.api;
  const amount = parseFloat(req.query.amount) || 10;

  const db = loadDB();
  const user = Object.values(db.users).find(u => u.apiKey === apiKey);

  if (!user) {
    return res.json({ status: 'error', message: 'Invalid API Key' });
  }

  const orderId = 'FAMPAY' + Date.now();
  const baseUrl = `${req.protocol}://${req.get('host')}`;

  orders.set(orderId, { upi: user.upi, amount, gmail: user.gmail, paid: false, createdAt: Date.now() });

  const response = {
    status: 'success',
    data: {
      order_id: orderId,
      qr_url: `${baseUrl}/qr/${orderId}.png`,
      upi_id: user.upi,
      amount,
      created_at_ist: new Date().toLocaleString('en-IN'),
      expires_at_ist: new Date(Date.now() + 300000).toLocaleString('en-IN')
    }
  };
  res.json(response);
});

// ====================== QR IMAGE (Real QR Code) ======================
app.get('/qr/:orderId.png', async (req, res) => {
  const orderId = req.params.orderId;
  const order = orders.get(orderId);

  let upiId = 'unknown@upi';
  let amount = 10;

  if (order) {
    upiId = order.upi;
    amount = order.amount;
  } else {
    const amtParam = parseFloat(req.query.amount) || 10;
    const upiParam = req.query.upi || 'unknown@upi';
    upiId = upiParam;
    amount = amtParam;
  }

  const amountFormatted = parseFloat(amount).toFixed(2);
  // pa (payee address) must NOT have @ encoded — UPI apps reject %40
  const encodedUpi = upiId.replace(/[^@a-zA-Z0-9._\-]/g, c => encodeURIComponent(c));
  const upiString = `upi://pay?pa=${encodedUpi}&pn=GMS%20Pay&am=${amountFormatted}&cu=INR&tn=${encodeURIComponent(orderId)}`;

  try {
    const qrDataUrl = await QRCode.toDataURL(upiString, {
      width: 300,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' }
    });

    const base64 = qrDataUrl.replace(/^data:image\/png;base64,/, '');
    const buf = Buffer.from(base64, 'base64');
    res.setHeader('Content-Type', 'image/png');
    res.send(buf);
  } catch (err) {
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// ====================== VERIFY ======================
app.get('/api/verify', (req, res) => {
  const apiKey = req.query.api_key;
  const orderId = req.query.order_id;

  if (!orderId) {
    return res.json({ status: 'error', message: 'order_id is required' });
  }

  const db = loadDB();
  const user = Object.values(db.users).find(u => u.apiKey === apiKey);

  if (!user) {
    return res.json({ status: 'error', message: 'Invalid API Key' });
  }

  const order = orders.get(orderId);

  if (!order) {
    return res.json({ status: 'error', message: 'Order not found. Generate a QR first.' });
  }

  const EXPIRY_MS = 5 * 60 * 1000;
  const isExpired = (Date.now() - order.createdAt) >= EXPIRY_MS;

  if (isExpired && !order.paid) {
    return res.json({
      status: 'expired',
      message: 'This QR code has expired. Please generate a new one.',
      order_id: orderId
    });
  }

  if (order.paid) {
    return res.json({
      status: 'success',
      data: {
        order_id: orderId,
        transaction_id: order.transaction_id,
        amount: order.amount,
        utr: order.utr,
        sender_name: order.sender_name,
        payment_time_ist: order.payment_time_ist
      }
    });
  }

  const remainingMs = Math.max(0, (order.createdAt + EXPIRY_MS) - Date.now());
  return res.json({
    status: 'pending',
    message: 'Payment not received yet. Please complete the UPI payment and try again.',
    order_id: orderId,
    expires_in_ms: remainingMs
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`GMS FamPay API running on port ${PORT}`);
});
