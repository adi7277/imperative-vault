CREATE DATABASE IF NOT EXISTS vault_db;
USE vault_db;

CREATE TABLE IF NOT EXISTS users (
  id CHAR(36) PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  role VARCHAR(50) NOT NULL DEFAULT 'member',
  public_key TEXT NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  private_key_iv VARCHAR(64) NOT NULL,
  auth_hash VARCHAR(255) NOT NULL,
  salt VARCHAR(64) NOT NULL,
  branch_location VARCHAR(100) NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vault_items (
  id CHAR(36) PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  item_type VARCHAR(50) NOT NULL,
  category VARCHAR(50) NULL,
  location VARCHAR(100) NOT NULL,
  branch_location VARCHAR(100) NULL,
  folder_id CHAR(36) NULL,
  encrypted_payload LONGTEXT NOT NULL,
  encrypted_data LONGTEXT NULL,
  iv VARCHAR(64) NOT NULL,
  auth_tag VARCHAR(64) NOT NULL,
  created_by CHAR(36) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS item_access (
  id CHAR(36) PRIMARY KEY,
  vault_item_id CHAR(36) NOT NULL,
  user_id CHAR(36) NOT NULL,
  encrypted_dek TEXT NOT NULL,
  permission VARCHAR(50) NOT NULL DEFAULT 'owner',
  time_span VARCHAR(50) NULL,
  expires_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_item_user (vault_item_id, user_id)
);

CREATE TABLE IF NOT EXISTS shared_records (
  id CHAR(36) PRIMARY KEY,
  vault_item_id CHAR(36) NOT NULL,
  user_id CHAR(36) NOT NULL,
  shared_by CHAR(36) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id CHAR(36) PRIMARY KEY,
  user_id CHAR(36) NULL,
  action VARCHAR(100) NOT NULL,
  target_id CHAR(36) NULL,
  details TEXT NULL,
  ip_address VARCHAR(64) NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);