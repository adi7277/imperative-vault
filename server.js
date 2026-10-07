const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const mysql = require('mysql2/promise');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '4a2f8c9b1d7e3a5f60b8c4d2e1a3f5b7c9d0e2a4f6b8c1d3e5f7a9b0c2d4e6f8';

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT) || 4000,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'test',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  }
});

console.log(`[DB INIT] Connecting to host: ${process.env.DB_HOST || '127.0.0.1'} with SSL enabled.`);

// Auto-migrate schema
async function autoMigrate() {
  try {
    await pool.query("ALTER TABLE vault_items ADD COLUMN location VARCHAR(64) NOT NULL DEFAULT 'Pune'");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE item_access ADD COLUMN expires_at DATETIME NULL");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE item_access ADD COLUMN shared_by CHAR(36) NULL");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE item_access ADD COLUMN time_span VARCHAR(32) NOT NULL DEFAULT 'Permanent'");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(45) NULL");
  } catch (err) {}

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id CHAR(36) PRIMARY KEY,
        user_id CHAR(36) NULL,
        action VARCHAR(64) NOT NULL,
        item_id CHAR(36) NULL,
        details TEXT NULL,
        ip_address VARCHAR(45) NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  } catch (err) {}

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS shared_records (
        id CHAR(36) PRIMARY KEY,
        vault_item_id CHAR(36) NOT NULL,
        recipient_name VARCHAR(128) NOT NULL,
        shared_by CHAR(36) NULL,
        share_channel VARCHAR(32) DEFAULT 'WhatsApp',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_item_id (vault_item_id)
      )
    `);
  } catch (err) {}

  // Migrate shared_records for recipient editing and validity
  try {
    await pool.query("ALTER TABLE shared_records ADD COLUMN phone_number VARCHAR(32) NULL");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE shared_records ADD COLUMN department VARCHAR(64) NULL");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE shared_records ADD COLUMN time_span VARCHAR(32) NOT NULL DEFAULT 'Permanent'");
  } catch (err) {}

  try {
    await pool.query("ALTER TABLE shared_records ADD COLUMN expires_at DATETIME NULL");
  } catch (err) {}

  console.log('Database migrated: Enhanced shared user tracking and audit logs active');
}
autoMigrate();

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '25mb' }));
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  const filePath = path.join(__dirname, 'index.html');
  if (fs.existsSync(filePath)) return res.sendFile(filePath);
  return res.status(404).send('index.html not found.');
});

// Audit Log Writer with IPv4 normalization
async function writeAuditLog(userId, action, itemId = null, details = null, req = null) {
  try {
    let rawIp = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '') : '127.0.0.1';
    rawIp = rawIp.replace('::ffff:', '').trim();
    if (rawIp === '::1' || rawIp === '127.0.0.1' || !rawIp) {
      rawIp = '127.0.0.1 (Localhost)';
    }

    const detailStr = typeof details === 'object' && details !== null 
      ? JSON.stringify(details) 
      : String(details || '');

    await pool.execute(
      'INSERT INTO audit_logs (id, user_id, action, item_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
      [crypto.randomUUID(), userId || null, action, itemId || null, detailStr, rawIp]
    );
  } catch (err) {
    console.error('Audit log error:', err.message);
  }
}

function calculateExpiry(timeSpan) {
  if (!timeSpan || timeSpan === 'Permanent') return null;
  const now = new Date();
  switch (timeSpan) {
    case '1_hour': return new Date(now.getTime() + 1 * 60 * 60 * 1000);
    case '4_hours': return new Date(now.getTime() + 4 * 60 * 60 * 1000);
    case '8_hours': return new Date(now.getTime() + 8 * 60 * 60 * 1000);
    case '24_hours': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case '7_days': return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case '30_days': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    default: return null;
  }
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session token' });
  }
}

// ----------------------------------------------------
// 1. AUTHENTICATION
// ----------------------------------------------------

app.post('/api/v1/auth/login', async (req, res) => {
  const { username, master_password } = req.body;
  if (!username || !master_password) {
    return res.status(400).json({ error: 'Username and master_password are required' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, username, email, role, public_key, encrypted_private_key, private_key_iv, auth_hash, salt FROM users WHERE username = ? AND is_active = 1',
      [username]
    );

    if (!rows || rows.length === 0) {
      await writeAuditLog(null, 'AUTH_FAILED', null, { username, reason: 'Invalid user or deactivated' }, req);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = rows[0];
    const passwordMatch = await argon2.verify(user.auth_hash, master_password);
    if (!passwordMatch) {
      await writeAuditLog(user.id, 'AUTH_FAILED', null, { username, reason: 'Incorrect portal password' }, req);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    await writeAuditLog(user.id, 'AUTH_LOGIN_SUCCESS', null, { username: user.username, role: user.role }, req);

    return res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        encrypted_private_key: user.encrypted_private_key,
        private_key_iv: user.private_key_iv,
        salt: user.salt,
        public_key: user.public_key,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error during authentication' });
  }
});

// ----------------------------------------------------
// 2. VAULT ITEMS
// ----------------------------------------------------

app.get('/api/v1/vault/items', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const isAdmin = req.user.role === 'admin';

  try {
    const query = `
      SELECT 
        vi.id,
        vi.folder_id,
        COALESCE(vi.location, 'Pune') AS location,
        vi.title,
        vi.item_type,
        vi.encrypted_payload,
        vi.iv,
        vi.auth_tag,
        vi.created_at,
        vi.updated_at,
        ia.encrypted_dek,
        ia.permission,
        ia.time_span,
        ia.expires_at,
        (SELECT COUNT(*) FROM shared_records WHERE vault_item_id = vi.id) AS recipient_count
      FROM vault_items vi
      INNER JOIN item_access ia ON vi.id = ia.vault_item_id
      WHERE ia.user_id = ?
        ${!isAdmin ? 'AND (ia.expires_at IS NULL OR ia.expires_at > NOW())' : ''}
      ORDER BY vi.created_at DESC;
    `;
    const [rows] = await pool.query(query, [userId]);
    return res.json({ items: rows });
  } catch (err) {
    console.error('Fetch items error:', err);
    return res.status(500).json({ error: 'Internal server error fetching credentials' });
  }
});

app.post('/api/v1/vault/items', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Only admins can create credentials' });
  }

  const { title, item_type, location, encrypted_payload, iv, auth_tag, keys, time_span, system_ip } = req.body;
  const creatorId = req.user.id;
  const itemLocation = location || 'Pune';
  const selectedTimeSpan = time_span || 'Permanent';
  const expiresAt = calculateExpiry(selectedTimeSpan);

  if (!title || !item_type || !encrypted_payload || !iv || !auth_tag || !Array.isArray(keys) || keys.length === 0) {
    return res.status(400).json({ error: 'Missing required payload parameters' });
  }

  const itemId = crypto.randomUUID();
  let connection;

  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    await connection.execute(
      `INSERT INTO vault_items (id, title, item_type, location, encrypted_payload, iv, auth_tag, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [itemId, title, item_type, itemLocation, encrypted_payload, iv, auth_tag, creatorId]
    );

    for (const k of keys) {
      const isCreator = k.user_id === creatorId;
      const userSpan = isCreator ? 'Permanent' : selectedTimeSpan;
      const userExpiry = isCreator ? null : expiresAt;

      await connection.execute(
        `INSERT INTO item_access (id, vault_item_id, user_id, encrypted_dek, permission, shared_by, time_span, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [crypto.randomUUID(), itemId, k.user_id, k.encrypted_dek, k.permission || 'read', creatorId, userSpan, userExpiry]
      );
    }

    await connection.commit();

    await writeAuditLog(creatorId, 'CREDENTIAL_CREATED', itemId, {
      title,
      type: item_type,
      location: itemLocation,
      system_ip: system_ip || 'N/A',
      approval: selectedTimeSpan,
      shared_with: `${keys.length} team members`
    }, req);

    return res.status(201).json({ success: true, item_id: itemId });
  } catch (err) {
    if (connection) await connection.rollback();
    console.error('Save item error:', err);
    return res.status(500).json({ error: err.sqlMessage || err.message || 'Failed to store credential' });
  } finally {
    if (connection) connection.release();
  }
});

app.put('/api/v1/vault/items/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Only admins can edit credentials' });
  }

  const { id } = req.params;
  const { title, item_type, location, encrypted_payload, iv, auth_tag, system_ip } = req.body;
  const itemLocation = location || 'Pune';

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    await connection.execute(
      `UPDATE vault_items 
       SET title = ?, item_type = ?, location = ?, encrypted_payload = ?, iv = ?, auth_tag = ?
       WHERE id = ?`,
      [title, item_type, itemLocation, encrypted_payload, iv, auth_tag, id]
    );

    await connection.commit();

    await writeAuditLog(req.user.id, 'CREDENTIAL_UPDATED', id, {
      title,
      type: item_type,
      location: itemLocation,
      system_ip: system_ip || 'N/A'
    }, req);

    return res.json({ success: true, message: 'Credential updated successfully' });
  } catch (err) {
    if (connection) await connection.rollback();
    return res.status(500).json({ error: 'Failed to update credential' });
  } finally {
    if (connection) connection.release();
  }
});

app.delete('/api/v1/vault/items/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Only admins can delete credentials' });
  }

  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT title FROM vault_items WHERE id = ?', [id]);
    const title = rows.length > 0 ? rows[0].title : id;

    await pool.execute('DELETE FROM vault_items WHERE id = ?', [id]);
    await pool.execute('DELETE FROM shared_records WHERE vault_item_id = ?', [id]);
    await writeAuditLog(req.user.id, 'CREDENTIAL_DELETED', id, { title }, req);

    return res.json({ success: true, message: 'Credential deleted successfully' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete credential' });
  }
});

// ----------------------------------------------------
// 3. EDIT SHARED PASSWORD'S USER & RECIPIENT MANAGEMENT
// ----------------------------------------------------

// Record a new shared person
app.post('/api/v1/vault/items/:id/log-share', requireAuth, async (req, res) => {
  const itemId = req.params.id;
  const { recipient_name, phone_number, department, time_span, share_channel, system_ip } = req.body;

  if (!recipient_name || !recipient_name.trim()) {
    return res.status(400).json({ error: 'Recipient name is required' });
  }

  const cleanName = recipient_name.trim();
  const selectedSpan = time_span || 'Permanent';
  const expiresAt = calculateExpiry(selectedSpan);

  try {
    const shareId = crypto.randomUUID();

    await pool.execute(
      `INSERT INTO shared_records 
        (id, vault_item_id, recipient_name, phone_number, department, time_span, expires_at, shared_by, share_channel) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [shareId, itemId, cleanName, phone_number || null, department || null, selectedSpan, expiresAt, req.user.id, share_channel || 'WhatsApp']
    );

    const [itemRows] = await pool.query('SELECT title, location FROM vault_items WHERE id = ?', [itemId]);
    const itemTitle = itemRows.length > 0 ? itemRows[0].title : 'Asset';
    const itemLocation = itemRows.length > 0 ? itemRows[0].location : 'N/A';

    await writeAuditLog(req.user.id, 'PASSWORD_SHARED', itemId, {
      shared_with: cleanName,
      department: department || 'General',
      phone: phone_number || 'N/A',
      validity: selectedSpan,
      channel: share_channel || 'WhatsApp',
      target: itemTitle,
      location: itemLocation,
      system_ip: system_ip || 'N/A'
    }, req);

    const [countRows] = await pool.query('SELECT COUNT(*) as total FROM shared_records WHERE vault_item_id = ?', [itemId]);
    return res.json({ success: true, total_shares: countRows[0].total });
  } catch (err) {
    console.error('Record share error:', err);
    return res.status(500).json({ error: 'Failed to record share event' });
  }
});

// Get all shared users for an asset
app.get('/api/v1/vault/items/:id/shares', requireAuth, async (req, res) => {
  const itemId = req.params.id;
  try {
    const [rows] = await pool.query(`
      SELECT 
        sr.id, 
        sr.recipient_name, 
        sr.phone_number,
        sr.department,
        sr.time_span,
        sr.expires_at,
        sr.share_channel, 
        sr.created_at, 
        u.username as shared_by_name,
        CASE 
          WHEN sr.expires_at IS NULL THEN 'Permanent'
          WHEN sr.expires_at > NOW() THEN 'Active'
          ELSE 'Expired'
        END AS status
      FROM shared_records sr
      LEFT JOIN users u ON sr.shared_by = u.id
      WHERE sr.vault_item_id = ?
      ORDER BY sr.created_at DESC
    `, [itemId]);
    return res.json({ shares: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch share history' });
  }
});

// EDIT SHARED PASSWORD'S USER
app.put('/api/v1/vault/shares/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Administrator role required' });
  }

  const { id } = req.params;
  const { recipient_name, phone_number, department, time_span, share_channel } = req.body;

  if (!recipient_name || !recipient_name.trim()) {
    return res.status(400).json({ error: 'Recipient name cannot be empty' });
  }

  try {
    const [existing] = await pool.query(`
      SELECT sr.*, vi.title 
      FROM shared_records sr
      LEFT JOIN vault_items vi ON sr.vault_item_id = vi.id
      WHERE sr.id = ?
    `, [id]);

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Shared user record not found' });
    }

    const prev = existing[0];
    const selectedSpan = time_span || prev.time_span || 'Permanent';
    const expiresAt = calculateExpiry(selectedSpan);

    await pool.execute(
      `UPDATE shared_records 
       SET recipient_name = ?, phone_number = ?, department = ?, time_span = ?, expires_at = ?, share_channel = ?
       WHERE id = ?`,
      [recipient_name.trim(), phone_number || null, department || null, selectedSpan, expiresAt, share_channel || 'WhatsApp', id]
    );

    // Audit log the edit
    await writeAuditLog(req.user.id, 'SHARED_USER_UPDATED', prev.vault_item_id, {
      target: prev.title || 'Asset',
      previous_user: {
        recipient: prev.recipient_name,
        department: prev.department || 'N/A',
        phone: prev.phone_number || 'N/A',
        time_span: prev.time_span
      },
      updated_user: {
        recipient: recipient_name.trim(),
        department: department || 'N/A',
        phone: phone_number || 'N/A',
        time_span: selectedSpan,
        channel: share_channel || 'WhatsApp'
      }
    }, req);

    return res.json({ success: true, message: 'Shared password user updated successfully' });
  } catch (err) {
    console.error('Update shared user error:', err);
    return res.status(500).json({ error: 'Failed to update shared user' });
  }
});

// Delete shared user record
app.delete('/api/v1/vault/shares/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Administrator role required' });
  }

  const { id } = req.params;

  try {
    const [existing] = await pool.query(`
      SELECT sr.recipient_name, sr.vault_item_id, vi.title
      FROM shared_records sr
      LEFT JOIN vault_items vi ON sr.vault_item_id = vi.id
      WHERE sr.id = ?
    `, [id]);

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Shared user record not found' });
    }

    const recipientName = existing[0].recipient_name;
    const itemId = existing[0].vault_item_id;
    const itemTitle = existing[0].title || 'Asset';

    await pool.execute('DELETE FROM shared_records WHERE id = ?', [id]);

    await writeAuditLog(req.user.id, 'SHARED_USER_DELETED', itemId, {
      target: itemTitle,
      deleted_user: recipientName
    }, req);

    return res.json({ success: true, message: 'Shared user removed' });
  } catch (err) {
    console.error('Delete shared user error:', err);
    return res.status(500).json({ error: 'Failed to delete shared user' });
  }
});

// ----------------------------------------------------
// 4. AUDIT LOGS ENDPOINTS
// ----------------------------------------------------

app.get('/api/v1/logs', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Administrator role required' });
  }

  try {
    const query = `
      SELECT 
        al.id,
        al.timestamp,
        al.action,
        al.ip_address,
        al.details,
        al.item_id,
        u.username AS operator_name,
        u.role AS operator_role,
        vi.title AS target_item_title
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      LEFT JOIN vault_items vi ON al.item_id = vi.id
      ORDER BY al.timestamp DESC
      LIMIT 200;
    `;
    const [rows] = await pool.query(query);
    return res.json({ logs: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

app.post('/api/v1/logs/event', requireAuth, async (req, res) => {
  const { action, item_id, details } = req.body;
  if (!action) return res.status(400).json({ error: 'Action required' });

  await writeAuditLog(req.user.id, action, item_id || null, details || null, req);
  return res.json({ success: true });
});

// ----------------------------------------------------
// 5. USER MANAGEMENT & BATCH KEYS
// ----------------------------------------------------

app.get('/api/v1/users/public-keys', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, username, email, role, public_key FROM users WHERE is_active = 1 AND public_key IS NOT NULL ORDER BY username ASC'
    );
    return res.json({ users: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch public keys' });
  }
});

app.get('/api/v1/users', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  try {
    const [rows] = await pool.query(
      'SELECT id, username, email, role, is_active, created_at FROM users ORDER BY created_at DESC'
    );
    return res.json({ users: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/v1/users', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });

  const { username, email, password, role, public_key, encrypted_private_key, private_key_iv, salt } = req.body;
  if (!username || !email || !password || !public_key || !encrypted_private_key || !private_key_iv || !salt) {
    return res.status(400).json({ error: 'Missing required user parameters' });
  }

  try {
    const authHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    });

    const newUserId = crypto.randomUUID();
    const userRole = role === 'admin' ? 'admin' : 'member';

    await pool.execute(
      `INSERT INTO users (
        id, username, email, role, public_key, 
        encrypted_private_key, private_key_iv, auth_hash, salt, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      [newUserId, username, email, userRole, public_key, encrypted_private_key, private_key_iv, authHash, salt]
    );

    await writeAuditLog(req.user.id, 'USER_CREATED', null, { new_username: username, email, role: userRole }, req);
    return res.status(201).json({ success: true, user_id: newUserId });
  } catch (err) {
    return res.status(500).json({ error: 'User creation failed (username/email may exist)' });
  }
});

app.put('/api/v1/users/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  const { id } = req.params;
  const { role, is_active } = req.body;

  try {
    await pool.execute('UPDATE users SET role = ?, is_active = ? WHERE id = ?', [role, is_active, id]);
    await writeAuditLog(req.user.id, 'USER_STATUS_UPDATED', null, { target_user_id: id, role, is_active }, req);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/v1/users/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  const { id } = req.params;
  if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete own account' });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    await connection.execute('DELETE FROM item_access WHERE user_id = ?', [id]);
    await connection.execute('DELETE FROM users WHERE id = ?', [id]);
    await connection.commit();

    await writeAuditLog(req.user.id, 'USER_DELETED', null, { deleted_user_id: id }, req);
    return res.json({ success: true });
  } catch (err) {
    if (connection) await connection.rollback();
    return res.status(500).json({ error: 'Failed to delete user' });
  } finally {
    if (connection) connection.release();
  }
});

app.get('/api/v1/vault/missing-access', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  try {
    const query = `
      SELECT 
        vi.id AS vault_item_id,
        vi.title,
        u.id AS user_id,
        u.username,
        u.role,
        u.public_key
      FROM vault_items vi
      CROSS JOIN users u
      WHERE u.is_active = 1
        AND u.public_key IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM item_access ia 
          WHERE ia.vault_item_id = vi.id AND ia.user_id = u.id
        );
    `;
    const [rows] = await pool.query(query);
    return res.json({ missing: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to check missing access' });
  }
});

app.post('/api/v1/vault/batch-assign-keys', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  const { assignments } = req.body;
  if (!Array.isArray(assignments) || assignments.length === 0) return res.json({ success: true, count: 0 });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    for (const a of assignments) {
      await connection.execute('DELETE FROM item_access WHERE vault_item_id = ? AND user_id = ?', [a.vault_item_id, a.user_id]);
      await connection.execute(
        `INSERT INTO item_access (id, vault_item_id, user_id, encrypted_dek, permission, shared_by, time_span, expires_at) 
         VALUES (?, ?, ?, ?, ?, ?, 'Permanent', NULL)`,
        [crypto.randomUUID(), a.vault_item_id, a.user_id, a.encrypted_dek, a.permission || 'read', req.user.id]
      );
    }

    await connection.commit();
    return res.json({ success: true, count: assignments.length });
  } catch (err) {
    if (connection) await connection.rollback();
    return res.status(500).json({ error: 'Failed to assign keys' });
  } finally {
    if (connection) connection.release();
  }
});

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'unhealthy', error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Imperative Portal online at http://localhost:${PORT}`);
});