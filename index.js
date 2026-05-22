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

const pendingOrders = new Map();

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
app.post('/auth/signup', async (req, res) => {
  const { gmail, upi, password } = req.body;
  if (!gmail || !upi || !password) {
    return res.json({ status: 'error', message: 'All fields are required' });
  }
  if (password.length < 6) {
    return res.json({ status: 'error', message: 'Password must be at least 6 characters' });
  }

  const db = loadDB();
  const key = gmail.toLowerCase().trim();

  if (db.users[key]) {
    return res.json({ status: 'error', message: 'Account already exists. Please login.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const apiKey = generateApiKey();

  db.users[key] = {
    gmail: key,
    upi: upi.toLowerCase().trim(),
    password: hashedPassword,
    apiKey,
    createdAt: new Date().toISOString()
  };

  saveDB(db);

  const token = jwt.sign({ gmail: key }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    status: 'success',
    message: 'Account created successfully!',
    token,
    user: { gmail: key, upi: upi.toLowerCase().trim(), apiKey }
  });
});

// ====================== LOGIN ======================
app.post('/auth/login', async (req, res) => {
  const { gmail, password } = req.body;
  if (!gmail || !password) {
    return res.json({ status: 'error', message: 'Email and password are required' });
  }

  const db = loadDB();
  const key = gmail.toLowerCase().trim();
  const user = db.users[key];

  if (!user) {
    return res.json({ status: 'error', message: 'No account found with this email' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.json({ status: 'error', message: 'Incorrect password' });
  }

  const token = jwt.sign({ gmail: key }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    status: 'success',
    message: 'Logged in successfully!',
    token,
    user: { gmail: user.gmail, upi: user.upi, apiKey: user.apiKey }
  });
});

// ====================== GET PROFILE ======================
app.get('/auth/me', authMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users[req.userId];
  if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
  res.json({
    status: 'success',
    user: { gmail: user.gmail, upi: user.upi, apiKey: user.apiKey, createdAt: user.createdAt }
  });
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

  pendingOrders.set(orderId, { upi: user.upi, amount, gmail: user.gmail });

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
  const order = pendingOrders.get(orderId);

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

  const upiString = `upi://pay?pa=${upiId}&pn=GMS Pay&am=${amount}&cu=INR&tn=Order ${orderId}`;

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

  const db = loadDB();
  const user = Object.values(db.users).find(u => u.apiKey === apiKey);

  if (!user) {
    return res.json({ status: 'error', message: 'Invalid API Key' });
  }

  const isSuccess = Math.random() > 0.35;

  if (isSuccess) {
    res.json({
      status: 'success',
      data: {
        order_id: orderId,
        transaction_id: 'FMPIB' + Math.floor(Math.random() * 1000000000),
        amount: pendingOrders.get(orderId)?.amount || 10,
        utr: '3' + Math.floor(Math.random() * 10000000000),
        sender_name: 'Test User',
        payment_time_ist: new Date().toLocaleString('en-IN')
      }
    });
  } else {
    res.json({
      status: 'pending',
      message: 'Payment verification in progress',
      order_id: orderId
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`GMS FamPay API running on port ${PORT}`);
});
