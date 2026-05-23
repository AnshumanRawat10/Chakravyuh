const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'CHAKRAVYUH_SECRET_KEY_CLASSIFIED_98321';

// Setup directories
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve public files if needed
app.use('/uploads', express.static(UPLOADS_DIR));

// Helper: Get IP and Device Info from request
function getRequestInfo(req) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const device = req.headers['user-agent'] || 'Unknown Device';
  return { ip, device };
}

// Helper: Log activities
function logActivity(user, filename, action, status, securityLevel = 'N/A', failedAttempts = 0, ip = '127.0.0.1', device = 'Unknown') {
  db.logs.insertOne({
    user,
    filename,
    action,
    status,
    securityLevel,
    failedAttempts,
    ip,
    device,
    timestamp: new Date().toISOString()
  });
}

// Middleware: Verify JWT Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'ACCESS DENIED: No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'ACCESS DENIED: Invalid or expired token.' });
    }
    
    // Check if account is locked or disabled
    const user = db.users.findOne({ email: decoded.email });
    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }
    
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      return res.status(403).json({ error: 'Session suspended. Account locked.' });
    }

    req.user = user;
    next();
  });
}

// Middleware: Require Operator Role
function requireOperator(req, res, next) {
  if (req.user.role !== 'operator') {
    return res.status(403).json({ error: 'RESTRICTED AREA: Operator permissions required.' });
  }
  next();
}

// Multer Storage Configuration (Staged unencrypted temporarily before immediate encryption)
const tempStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'temp_' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: tempStorage });

// --- AUTHENTICATION ROUTES ---

// Email Regex: Name.MilitaryUnit@army.Rank
const EMAIL_REGEX = /^([A-Za-z0-9]+)\.([A-Za-z0-9_-]+)@army\.([A-Za-z0-9]+)$/;

// Password Regex: MIL-[RANK]-[4 Digit Code]-[Special Symbol]
// Minimal length: 12 chars
function validatePasswordStructure(password, rank) {
  if (password.length < 12) return false;
  if (!password.startsWith('MIL-')) return false;
  
  // Extract rank, code and symbol
  // Form: MIL-[RANK]-[4 digits]-[special symbol]
  // e.g. MIL-CAPT-1947# or MIL-OPERATOR-1947#
  // We can check if it contains rank (case insensitive)
  const normalizedPass = password.toUpperCase();
  const normalizedRank = rank.toUpperCase();
  
  if (!normalizedPass.includes(normalizedRank)) return false;
  
  // Find a 4-digit code
  const codeMatch = password.match(/\d{4}/);
  if (!codeMatch) return false;
  
  // Special symbol check
  const specialSymbolMatch = password.match(/[-#@$!%*?&]/);
  if (!specialSymbolMatch) return false;
  
  return true;
}

// Login Endpoint
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const { ip, device } = getRequestInfo(req);

  // Validate Input
  if (!email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // 1. Check Email format
  const emailMatch = email.match(EMAIL_REGEX);
  if (!emailMatch) {
    // Log suspicious activity
    logActivity('CIVILIAN / INVALID', 'N/A', 'LOGIN_ATTEMPT', 'BLOCKED_INVALID_EMAIL', 'N/A', 1, ip, device);
    db.threats.insertOne({
      timestamp: new Date().toISOString(),
      type: 'Unauthorized Email Format Attempt',
      sourceIp: ip,
      targetUser: email,
      severity: 'HIGH',
      status: 'BLOCKED',
      device: device,
      description: `Civilian access attempt. Email failed military format: '${email}'`
    });

    return res.status(403).json({
      warningType: 'CIVILIAN_ENTRY_DETECTED',
      message: `⚠ RESTRICTED ACCESS\n\nUnauthorized civilian entry detected.\n\nThis network is protected under military-grade security protocols.\n\nIllegal access attempts are monitored and logged.`
    });
  }

  const [_, name, unit, rank] = emailMatch;

  // 2. Retrieve user
  const user = db.users.findOne({ email });
  if (!user) {
    // Log as suspicious, but return general error
    logActivity(email, 'N/A', 'LOGIN_ATTEMPT', 'FAILED_USER_NOT_FOUND', 'N/A', 1, ip, device);
    return res.status(401).json({ error: 'Access denied: Military credentials invalid.' });
  }

  // 3. Check Lockout Status
  if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
    const timeLeft = Math.ceil((new Date(user.lockedUntil) - new Date()) / 1000);
    return res.status(423).json({
      error: `Security lockout active. Try again in ${timeLeft} seconds.`
    });
  }

  // 4. Verify password structure
  if (!validatePasswordStructure(password, rank)) {
    // Increment failed attempts
    const newAttempts = (user.failedAttempts || 0) + 1;
    let lockUntil = null;
    let errorMsg = 'Access denied: Password does not match military security structure.';
    
    if (newAttempts >= 3) {
      lockUntil = new Date(Date.now() + 60000).toISOString(); // Lock for 60 seconds
      errorMsg = '⛔ CLASSIFIED NETWORK ACCESS DENIED\n\nUnauthorized authentication attempt detected.\n\nFurther attempts may trigger security lockdown.';
    }

    db.users.updateOne({ email }, { failedAttempts: newAttempts, lockedUntil: lockUntil });
    
    // Log warning
    logActivity(email, 'N/A', 'LOGIN_ATTEMPT', 'FAILED_PASSWORD_STRUCTURE', 'N/A', newAttempts, ip, device);
    db.threats.insertOne({
      timestamp: new Date().toISOString(),
      type: 'Invalid Password Format Attempt',
      sourceIp: ip,
      targetUser: email,
      severity: newAttempts >= 3 ? 'CRITICAL' : 'MEDIUM',
      status: lockUntil ? 'LOCKOUT_TRIGGERED' : 'MONITORED',
      device: device,
      description: `Failed login attempt ${newAttempts}/3. Password format rejected.`
    });

    if (newAttempts >= 3) {
      return res.status(403).json({
        warningType: 'CLASSIFIED_DENIED',
        message: errorMsg
      });
    }

    return res.status(401).json({ error: errorMsg });
  }

  // 5. Verify password hash
  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) {
    const newAttempts = (user.failedAttempts || 0) + 1;
    let lockUntil = null;
    let errorMsg = 'Access denied: Military credentials invalid.';

    if (newAttempts >= 3) {
      lockUntil = new Date(Date.now() + 60000).toISOString();
      errorMsg = '⛔ CLASSIFIED NETWORK ACCESS DENIED\n\nUnauthorized authentication attempt detected.\n\nFurther attempts may trigger security lockdown.';
    }

    db.users.updateOne({ email }, { failedAttempts: newAttempts, lockedUntil: lockUntil });
    logActivity(email, 'N/A', 'LOGIN_ATTEMPT', 'FAILED_PASSWORD_HASH', 'N/A', newAttempts, ip, device);
    db.threats.insertOne({
      timestamp: new Date().toISOString(),
      type: 'Invalid Credentials',
      sourceIp: ip,
      targetUser: email,
      severity: newAttempts >= 3 ? 'CRITICAL' : 'MEDIUM',
      status: lockUntil ? 'LOCKOUT_TRIGGERED' : 'MONITORED',
      device: device,
      description: `Failed login attempt ${newAttempts}/3. Password mismatch.`
    });

    if (newAttempts >= 3) {
      return res.status(403).json({
        warningType: 'CLASSIFIED_DENIED',
        message: errorMsg
      });
    }

    return res.status(401).json({ error: errorMsg });
  }

  // Reset failed attempts on success
  db.users.updateOne({ email }, { failedAttempts: 0, lockedUntil: null });

  // Generate Token
  const token = jwt.sign(
    { id: user._id, email: user.email, role: user.role, name: user.name, rank: user.rank, unit: user.unit },
    JWT_SECRET,
    { expiresIn: '2h' }
  );

  logActivity(email, 'N/A', 'LOGIN_SUCCESS', 'SUCCESS', 'N/A', 0, ip, device);
  
  res.json({
    token,
    user: {
      id: user._id,
      email: user.email,
      role: user.role,
      name: user.name,
      rank: user.rank,
      unit: user.unit
    }
  });
});

// User registration endpoint (accessible only by Operator)
app.post('/api/auth/register', authenticateToken, requireOperator, (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const emailMatch = email.match(EMAIL_REGEX);
  if (!emailMatch) {
    return res.status(400).json({ error: 'Email format must be Name.Unit@army.Rank' });
  }

  const [_, parsedName, unit, rank] = emailMatch;

  if (!validatePasswordStructure(password, rank)) {
    return res.status(400).json({ 
      error: 'Password must match format MIL-[RANK]-[4 digits]-[symbol] and be at least 12 characters.' 
    });
  }

  const existingUser = db.users.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ error: 'Military personnel already registered.' });
  }

  const salt = bcrypt.genSaltSync(10);
  const newUser = db.users.insertOne({
    email,
    password: bcrypt.hashSync(password, salt),
    role: 'user',
    name,
    rank,
    unit,
    failedAttempts: 0,
    lockedUntil: null
  });

  res.json({ success: true, user: { id: newUser._id, email: newUser.email, name: newUser.name } });
});

// --- FILE SECURE TRANSFER ROUTES ---

// Cryptographic encryption handler
function encryptFileBuffer(buffer, passkey) {
  const key = crypto.createHash('sha256').update(passkey).digest(); // 32 bytes
  const iv = crypto.randomBytes(16); // 16 bytes
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { encryptedBuffer: encrypted, ivHex: iv.toString('hex') };
}

// Cryptographic decryption handler
function decryptFileBuffer(buffer, passkey, ivHex) {
  const key = crypto.createHash('sha256').update(passkey).digest();
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  
  const decrypted = Buffer.concat([decipher.update(buffer), decipher.final()]);
  return decrypted;
}

// Upload File Endpoint
app.post('/api/files/upload', authenticateToken, upload.single('file'), (req, res) => {
  const { passkey, securityLevel, recipient, oneTimeDownload, expiryHours } = req.body;
  const { ip, device } = getRequestInfo(req);

  if (!req.file) {
    return res.status(400).json({ error: 'No file staged for transmission.' });
  }

  if (!passkey) {
    // Cleanup temporary file
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Decryption passkey is required to encrypt the payload.' });
  }

  try {
    const originalPath = req.file.path;
    const originalBuffer = fs.readFileSync(originalPath);
    
    // Encrypt the file buffer using the sender's custom passkey
    const { encryptedBuffer, ivHex } = encryptFileBuffer(originalBuffer, passkey);
    
    // Generate secure randomized filename on disk
    const secureFilename = 'enc_' + crypto.randomUUID() + '.dat';
    const securePath = path.join(UPLOADS_DIR, secureFilename);
    
    fs.writeFileSync(securePath, encryptedBuffer);
    
    // Clean up unencrypted file immediately
    fs.unlinkSync(originalPath);

    // Save DB Metadata
    const fileRecord = db.files.insertOne({
      filename: req.file.originalname,
      secureFilename,
      size: req.file.size,
      sender: req.user.email,
      recipient: recipient || 'all',
      securityLevel: securityLevel || 'Confidential',
      oneTimeDownload: oneTimeDownload === 'true' || oneTimeDownload === true,
      expiryHours: expiryHours ? parseInt(expiryHours) : null,
      iv: ivHex,
      passkeyHash: bcrypt.hashSync(passkey, 10), // Used to verify input key on download
      downloadedCount: 0,
      failedDecryptions: 0
    });

    logActivity(
      req.user.email,
      req.file.originalname,
      'FILE_UPLOAD',
      'SUCCESS',
      fileRecord.securityLevel,
      0,
      ip,
      device
    );

    res.json({
      success: true,
      file: {
        id: fileRecord._id,
        filename: fileRecord.filename,
        securityLevel: fileRecord.securityLevel,
        recipient: fileRecord.recipient,
        size: fileRecord.size,
        createdAt: fileRecord.createdAt
      }
    });
  } catch (err) {
    console.error('Upload encryption error', err);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'System encryption failure. File transmission aborted.' });
  }
});

// List Files Endpoint
app.get('/api/files', authenticateToken, (req, res) => {
  const files = db.files.find();
  
  // Filter based on roles
  if (req.user.role === 'operator') {
    return res.json(files);
  }

  // Military user can only see files sent by them or files assigned to them/all
  const filtered = files.filter(f => 
    f.sender === req.user.email || 
    f.recipient === req.user.email || 
    f.recipient === 'all'
  );
  
  res.json(filtered);
});

// Download & Decrypt File Endpoint
app.post('/api/files/download/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { passkey } = req.body;
  const { ip, device } = getRequestInfo(req);

  const file = db.files.findOne({ _id: id });
  if (!file) {
    return res.status(404).json({ error: 'Classified payload not found.' });
  }

  // Check role authorization
  if (req.user.role !== 'operator' && file.sender !== req.user.email && file.recipient !== req.user.email && file.recipient !== 'all') {
    return res.status(403).json({ error: 'RESTRICTED PAYLOAD: Access authorization denied.' });
  }

  // Check Expired file
  if (file.expiryHours) {
    const ageMs = Date.now() - new Date(file.createdAt).getTime();
    const expiryMs = file.expiryHours * 3600000;
    if (ageMs > expiryMs) {
      // Self-delete file
      try {
        const filePath = path.join(UPLOADS_DIR, file.secureFilename);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        db.files.deleteOne({ _id: id });
      } catch (e) {}
      return res.status(410).json({ error: 'payload self-destructed. File has expired.' });
    }
  }

  // Verify passkey
  const isValidPass = bcrypt.compareSync(passkey, file.passkeyHash);
  if (!isValidPass) {
    const failedCount = (file.failedDecryptions || 0) + 1;
    db.files.updateOne({ _id: id }, { failedDecryptions: failedCount });

    logActivity(
      req.user.email,
      file.filename,
      'FILE_DECRYPTION_ATTEMPT',
      'FAILED',
      file.securityLevel,
      failedCount,
      ip,
      device
    );

    // Create high-severity threat alert if 3 failed attempts
    if (failedCount >= 3) {
      db.threats.insertOne({
        timestamp: new Date().toISOString(),
        type: 'Failed Payload Decryption Threshold',
        sourceIp: ip,
        targetUser: req.user.email,
        severity: 'CRITICAL',
        status: 'FLAGGED',
        device: device,
        description: `Failed decryption attempt ${failedCount} on file '${file.filename}' (ID: ${file._id}). Threat lockout triggered.`
      });

      return res.status(403).json({
        warningType: 'DECRYPTION_ALERT',
        message: `⚠ SECURITY ALERT\n\nMultiple failed decryption attempts detected.\nActivity has been logged.\nAccess to payload temporarily suspended.`
      });
    }

    return res.status(401).json({
      warningType: 'DECRYPTION_FAILED',
      message: `❌ INVALID SECURITY CODE\n\nAccess to classified file denied.`
    });
  }

  // Reset failed decryptions on success
  db.files.updateOne({ _id: id }, { failedDecryptions: 0 });

  // Read and Decrypt physical file
  const filePath = path.join(UPLOADS_DIR, file.secureFilename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Encrypted file missing from filesystem.' });
  }

  try {
    const encryptedData = fs.readFileSync(filePath);
    const decryptedData = decryptFileBuffer(encryptedData, passkey, file.iv);

    // Handle One-Time Download self-destruct
    if (file.oneTimeDownload) {
      fs.unlinkSync(filePath);
      db.files.deleteOne({ _id: id });
      logActivity(
        req.user.email,
        file.filename,
        'FILE_DOWNLOAD_SELF_DESTRUCT',
        'SUCCESS_DECRYPTED',
        file.securityLevel,
        0,
        ip,
        device
      );
    } else {
      db.files.updateOne({ _id: id }, { downloadedCount: file.downloadedCount + 1 });
      logActivity(
        req.user.email,
        file.filename,
        'FILE_DOWNLOAD',
        'SUCCESS_DECRYPTED',
        file.securityLevel,
        0,
        ip,
        device
      );
    }

    // Send Decrypted file
    res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(decryptedData);

  } catch (err) {
    console.error('Decryption execution error', err);
    res.status(500).json({ error: 'Cryptographic execution failed during stream decryption.' });
  }
});

// Delete file endpoint
app.delete('/api/files/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { ip, device } = getRequestInfo(req);

  const file = db.files.findOne({ _id: id });
  if (!file) {
    return res.status(404).json({ error: 'File not found.' });
  }

  // Authorization check
  if (req.user.role !== 'operator' && file.sender !== req.user.email) {
    return res.status(403).json({ error: 'Access denied: Unauthorized operation.' });
  }

  try {
    const filePath = path.join(UPLOADS_DIR, file.secureFilename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    db.files.deleteOne({ _id: id });

    logActivity(
      req.user.email,
      file.filename,
      'FILE_DELETION',
      'SUCCESS',
      file.securityLevel,
      0,
      ip,
      device
    );

    res.json({ success: true, message: 'Payload scrubbed from secure server.' });
  } catch (e) {
    res.status(500).json({ error: 'Scrubbing failed.' });
  }
});

// --- ACTIVITY & THREAT LOGS ROUTES ---

// Get Live Logs Endpoint
app.get('/api/logs', authenticateToken, (req, res) => {
  const logs = db.logs.find();
  // Operator can see all logs; User can only see their own logs
  if (req.user.role === 'operator') {
    return res.json(logs);
  }
  
  const userLogs = logs.filter(log => log.user === req.user.email);
  res.json(userLogs);
});

// Get Live Threats (Operator Only)
app.get('/api/threats', authenticateToken, requireOperator, (req, res) => {
  res.json(db.threats.find());
});

// Simulate Cyber Attack Threat (Operator Only)
app.post('/api/threats/simulate', authenticateToken, requireOperator, (req, res) => {
  const { attackType } = req.body;
  const { ip, device } = getRequestInfo(req);
  
  let newThreat = {};
  const mockIps = ['198.51.100.42', '203.0.113.195', '192.0.2.78', '185.220.101.99'];
  const randomIp = mockIps[Math.floor(Math.random() * mockIps.length)];

  if (attackType === 'DDOS') {
    newThreat = {
      timestamp: new Date().toISOString(),
      type: 'DDoS Traffic Spike Alert',
      sourceIp: randomIp,
      targetUser: 'API_GATEWAY_NET',
      severity: 'CRITICAL',
      status: 'MITIGATED',
      device: 'Botnet/Mirai Variant',
      description: 'Incoming volumetric traffic exceed 15 Gbps. Rate limiting and Cloud Scrubber routing engaged.'
    };
  } else if (attackType === 'BRUTE_FORCE') {
    newThreat = {
      timestamp: new Date().toISOString(),
      type: 'Brute Force Breach Attempt',
      sourceIp: randomIp,
      targetUser: 'Vikram.SpecialForces@army.Colonel',
      severity: 'HIGH',
      status: 'BLOCKED',
      device: 'Hydra Script Tool',
      description: '15 sequential auth attempts detected in 4 seconds. Source IP auto-quarantined for 24h.'
    };
  } else if (attackType === 'SQL_INJECTION') {
    newThreat = {
      timestamp: new Date().toISOString(),
      type: 'SQL Injection Payload Blocked',
      sourceIp: randomIp,
      targetUser: 'database.js API Router',
      severity: 'HIGH',
      status: 'BLOCKED',
      device: 'OWASP ZAP / Linux',
      description: 'Malformed escape characters detected in parameter input. Payload scrubbed, connection terminated.'
    };
  } else {
    newThreat = {
      timestamp: new Date().toISOString(),
      type: 'AI Anomalous Pattern Detected',
      sourceIp: randomIp,
      targetUser: 'Secure_Log_Daemon',
      severity: 'MEDIUM',
      status: 'INVESTIGATING',
      device: 'Python requests client',
      description: 'Encrypted buffer structure query from unverified node. Tracking routing hops.'
    };
  }

  const inserted = db.threats.insertOne(newThreat);
  
  // Log simulated event
  logActivity('SYSTEM_DAEMON', 'N/A', 'THREAT_SIMULATION', 'ALERT_BROADCAST', 'N/A', 0, randomIp, newThreat.device);

  res.json({ success: true, threat: inserted });
});

// --- SETTINGS ROUTES ---

app.get('/api/settings', authenticateToken, (req, res) => {
  const currentSettings = db.settings.find()[0] || {};
  res.json(currentSettings);
});

app.put('/api/settings', authenticateToken, requireOperator, (req, res) => {
  const updatedSettings = req.body;
  const currentSettings = db.settings.find()[0];
  
  if (currentSettings) {
    db.settings.updateOne({ _id: currentSettings._id }, updatedSettings);
  } else {
    db.settings.insertOne(updatedSettings);
  }
  
  res.json({ success: true, settings: db.settings.find()[0] });
});

// --- AUTOMATIC CLEANUP CRON SIMULATION ---
// Checks for expired files and self-destructs them on a interval loop
setInterval(() => {
  const files = db.files.find();
  files.forEach(file => {
    if (file.expiryHours) {
      const ageMs = Date.now() - new Date(file.createdAt).getTime();
      const expiryMs = file.expiryHours * 3600000;
      if (ageMs > expiryMs) {
        try {
          const filePath = path.join(UPLOADS_DIR, file.secureFilename);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            console.log(`Self-destructed expired file: ${file.filename}`);
          }
          db.files.deleteOne({ _id: file._id });
          
          logActivity(
            'SYSTEM_DAEMON',
            file.filename,
            'FILE_SELF_DESTRUCT_EXPIRY',
            'SUCCESS',
            file.securityLevel,
            0,
            '127.0.0.1',
            'Internal Cron Daemon'
          );
        } catch (e) {
          console.error(`Failed to cleanup expired file ${file.filename}`, e);
        }
      }
    }
  });
}, 30000); // Run every 30 seconds

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`CHAKRAVYUH SECURE MILITARY BACKEND SERVER STARTING`);
  console.log(`PORT: ${PORT}`);
  console.log(`SECURITY PROTOCOL: ACTIVE (JWT + AES-256 + RATE CONTROL)`);
  console.log(`DATABASE STATE: persistence ONLINE (JSON File Storage)`);
  console.log(`=======================================================`);
});
