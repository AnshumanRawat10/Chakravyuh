const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DATA_DIR = path.join(__dirname, 'data');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

class Collection {
  constructor(name) {
    this.filePath = path.join(DATA_DIR, `${name}.json`);
    if (!fs.existsSync(this.filePath)) {
      fs.writeFileSync(this.filePath, JSON.stringify([], null, 2));
    }
  }

  read() {
    try {
      const data = fs.readFileSync(this.filePath, 'utf8');
      return JSON.parse(data);
    } catch (e) {
      console.error(`Error reading collection file ${this.filePath}`, e);
      return [];
    }
  }

  write(data) {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2));
    } catch (e) {
      console.error(`Error writing collection file ${this.filePath}`, e);
    }
  }

  find(query = {}) {
    const items = this.read();
    return items.filter(item => {
      for (let key in query) {
        if (item[key] !== query[key]) return false;
      }
      return true;
    });
  }

  findOne(query = {}) {
    const items = this.read();
    return items.find(item => {
      for (let key in query) {
        if (item[key] !== query[key]) return false;
      }
      return true;
    }) || null;
  }

  insertOne(doc) {
    const items = this.read();
    const newDoc = {
      _id: Math.random().toString(36).substring(2, 9) + Date.now().toString(36),
      createdAt: new Date().toISOString(),
      ...doc
    };
    items.push(newDoc);
    this.write(items);
    return newDoc;
  }

  updateOne(query, update) {
    const items = this.read();
    const index = items.findIndex(item => {
      for (let key in query) {
        if (item[key] !== query[key]) return false;
      }
      return true;
    });

    if (index === -1) return null;
    items[index] = { ...items[index], ...update, updatedAt: new Date().toISOString() };
    this.write(items);
    return items[index];
  }

  deleteOne(query) {
    const items = this.read();
    const index = items.findIndex(item => {
      for (let key in query) {
        if (item[key] !== query[key]) return false;
      }
      return true;
    });

    if (index === -1) return false;
    items.splice(index, 1);
    this.write(items);
    return true;
  }
}

// Instantiate collections
const db = {
  users: new Collection('users'),
  files: new Collection('files'),
  logs: new Collection('logs'),
  threats: new Collection('threats'),
  settings: new Collection('settings')
};

// Seed initial users
function seedDatabase() {
  const salt = bcrypt.genSaltSync(10);
  
  // 1. Seed Operator
  const operatorEmail = 'Anshuman.CommandCenter@army.Operator';
  const existingOperator = db.users.findOne({ email: operatorEmail });
  if (!existingOperator) {
    db.users.insertOne({
      email: operatorEmail,
      password: bcrypt.hashSync('MIL-OPERATOR-1947#', salt),
      role: 'operator',
      name: 'Anshuman CommandCenter',
      rank: 'Operator',
      unit: 'CommandCenter',
      failedAttempts: 0,
      lockedUntil: null
    });
    console.log('Seeded Operator account');
  }

  // 2. Seed requested military users
  const usersToSeed = [
    {
      email: 'Rana.Gorkha@army.MajorGeneral',
      password: 'MIL-MAJORGENERAL-1001#',
      name: 'Rana',
      rank: 'MajorGeneral',
      unit: 'Gorkha'
    },
    {
      email: 'Singh.Rajputana@army.Brigadier',
      password: 'MIL-BRIGADIER-2002#',
      name: 'Singh',
      rank: 'Brigadier',
      unit: 'Rajputana'
    },
    {
      email: 'Shekhawat.Rajputana@army.Colonel',
      password: 'MIL-COLONEL-3003#',
      name: 'Shekhawat',
      rank: 'Colonel',
      unit: 'Rajputana'
    },
    {
      email: 'Sharma.Dogra@army.LieutenantGeneral',
      password: 'MIL-LIEUTENANTGENERAL-4004#',
      name: 'Sharma',
      rank: 'LieutenantGeneral',
      unit: 'Dogra'
    }
  ];

  usersToSeed.forEach(u => {
    if (!db.users.findOne({ email: u.email })) {
      db.users.insertOne({
        email: u.email,
        password: bcrypt.hashSync(u.password, salt),
        role: 'user',
        name: u.name,
        rank: u.rank,
        unit: u.unit,
        failedAttempts: 0,
        lockedUntil: null
      });
      console.log(`Seeded Military User (${u.email})`);
    }
  });

  // Delete ParachuteRegiment user if it exists from previous seed
  const paraUser = db.users.findOne({ email: 'Anshuman.ParachuteRegiment@army.Captain' });
  if (paraUser) {
    db.users.deleteOne({ email: 'Anshuman.ParachuteRegiment@army.Captain' });
    console.log('Removed old ParachuteRegiment account.');
  }

  // 3. Seed settings if not exist
  if (db.settings.find().length === 0) {
    db.settings.insertOne({
      sessionTimeout: 15, // in minutes
      expiringFilesDefault: 24, // in hours
      biometricMock: true,
      blockchainSimulation: true
    });
  }

  // 4. Seed threat analysis report/threat logs
  if (db.threats.find().length === 0) {
    const threats = [
      {
        timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
        type: 'Brute Force Attack Detected',
        sourceIp: '185.220.101.4',
        targetUser: 'Rahul.NorthernCommand@army.Major',
        severity: 'HIGH',
        status: 'BLOCKED',
        device: 'Mozilla/5.0 (Windows NT 10.0; Win64)',
        description: 'Failed login attempt pattern exceeded threshold. IP address temporarily banned.'
      },
      {
        timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
        type: 'Suspicious IP Country Access',
        sourceIp: '45.143.203.14',
        targetUser: 'Unknown / Civilian Credentials',
        severity: 'MEDIUM',
        status: 'MONITORED',
        device: 'curl/7.68.0',
        description: 'Access attempted from recognized Tor exit node. Auto-routing to honeypot.'
      },
      {
        timestamp: new Date(Date.now() - 3600000 * 6).toISOString(),
        type: 'Expiring File Self-Destructed',
        sourceIp: 'System Auto-Daemon',
        targetUser: 'N/A',
        severity: 'INFO',
        status: 'CLEARED',
        device: 'Internal Service',
        description: 'File ID: fl_9a8df02 (Operation_Red_Shield.pdf) reached expiry threshold. Overwritten and scrubbed from server.'
      }
    ];
    threats.forEach(t => db.threats.insertOne(t));
  }
}

seedDatabase();

module.exports = db;
