#!/usr/bin/env node

import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database path (same as db.js)
const dbPath = path.join(__dirname, '..', 'content.sqlite');

// Admin user credentials
const adminEmail = 'alexander@globalguidegroup.com';
const adminPassword = 'SecurePass123!';

console.log('🔧 GGG CMS - Admin User Creation Script');
console.log('=====================================');
console.log('🚀 Ready for Render deployment!');

try {
  // Connect to database
  const db = new Database(dbPath);
  console.log('✅ Connected to database');

  // Check if user already exists
  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
  
  if (existingUser) {
    console.log('❌ User with email already exists:', adminEmail);
    console.log('   Please use a different email or delete the existing user first.');
    process.exit(1);
  }

  // Hash password
  console.log('🔐 Hashing password...');
  const saltRounds = 10;
  const passwordHash = bcrypt.hashSync(adminPassword, saltRounds);

  // Insert new admin user
  console.log('👤 Creating admin user...');
  const insertUser = db.prepare(`
    INSERT INTO users (email, password_hash, created_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
  `);

  const result = insertUser.run(adminEmail, passwordHash);
  
  if (result.changes > 0) {
    console.log('✅ Admin user created successfully!');
    console.log('');
    console.log('📧 Email:', adminEmail);
    console.log('🔑 Password:', adminPassword);
    console.log('');
    console.log('⚠️  IMPORTANT: Please change the password after first login!');
    console.log('   Login at: http://localhost:3000/admin/login');
  } else {
    console.log('❌ Failed to create admin user');
    process.exit(1);
  }

  // Close database connection
  db.close();
  console.log('✅ Database connection closed');

} catch (error) {
  console.error('❌ Error creating admin user:', error.message);
  process.exit(1);
}
