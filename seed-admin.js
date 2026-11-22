require('dotenv').config();
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const argon2 = require('argon2');

async function seed() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'vault_db',
    ssl: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true
    }
  });

  const username = 'admin';
  const email = 'adityamarathe7277@gmail.com';
  const masterPassword = '#include<imp.h>';

  console.log('Generating 4096-bit RSA Admin Keypair (may take 5-10 seconds)...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const derivedKey = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, 'sha256');

  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
  let encryptedPrivateKey = cipher.update(privateKey, 'utf8', 'base64');
  encryptedPrivateKey += cipher.final('base64');
  const authTag = cipher.getAuthTag().toString('base64');

  const storedEncryptedPrivateKey = `${encryptedPrivateKey}:${authTag}`;

  const authHash = await argon2.hash(masterPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1
  });

  const adminId = crypto.randomUUID();

  await pool.execute('DELETE FROM users WHERE username = ?', [username]);
  await pool.execute(
    `INSERT INTO users (
      id, username, email, role, public_key,
      encrypted_private_key, private_key_iv, auth_hash, salt, branch_location, is_active
    ) VALUES (?, ?, ?, 'admin', ?, ?, ?, ?, ?, 'Pune', 1)`,
    [
      adminId,
      username,
      email,
      publicKey,
      storedEncryptedPrivateKey,
      iv.toString('hex'),
      authHash,
      salt.toString('hex')
    ]
  );

  console.log('Admin account created successfully.');
  console.log(`Username: ${username}`);
  console.log(`Email: ${email}`);
  await pool.end();
}

seed().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});