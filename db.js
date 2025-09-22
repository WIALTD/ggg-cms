import 'dotenv/config';
import Database from 'better-sqlite3';
import { marked } from 'marked';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Use persistent storage path in production, local path in development
const isProduction = process.env.NODE_ENV === 'production';
const dbPath = isProduction ? '/data/content.sqlite' : path.join(__dirname, 'content.sqlite');

const db = new Database(dbPath);

// Create posts table
db.exec(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    body_md TEXT NOT NULL,
    body_html TEXT NOT NULL,
    status TEXT DEFAULT 'draft',
    featured_image TEXT,
    published_at DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Create pages table
db.exec(`
  CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    body_md TEXT NOT NULL,
    body_html TEXT NOT NULL,
    status TEXT DEFAULT 'draft',
    published_at DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Check if we need to add featured_image column to existing posts table
try {
  db.prepare('SELECT featured_image FROM posts LIMIT 1').get();
} catch (error) {
  // Column doesn't exist, add it
  db.exec('ALTER TABLE posts ADD COLUMN featured_image TEXT');
  console.log('Added featured_image column to posts table');
}

// Check if we need to seed data
const postCount = db.prepare('SELECT COUNT(*) as count FROM posts').get();
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();

if (postCount.count === 0) {
  const florenceMarkdown = `# Florence Guide

Florence, the capital of Italy's Tuscany region, is a city that captures the essence of Renaissance art and culture. Known as the "Cradle of the Renaissance," Florence is home to some of the world's most famous artworks and architectural masterpieces.

## Must-See Attractions

### Uffizi Gallery
The Uffizi Gallery houses one of the most important collections of Renaissance art in the world. Here you'll find masterpieces by Botticelli, Michelangelo, and Leonardo da Vinci.

### Duomo (Cathedral of Santa Maria del Fiore)
The iconic red-tiled dome of Florence's cathedral dominates the city skyline. Climb to the top for breathtaking views of the city.

### Ponte Vecchio
This medieval stone bridge spans the Arno River and is famous for its jewelry shops built along its length.

## Local Cuisine

Don't miss trying:
- **Bistecca alla Fiorentina** - A thick T-bone steak grilled over high heat
- **Ribollita** - A hearty vegetable and bread soup
- **Gelato** - Florence is known for its artisanal gelato

## Getting Around

Florence is a walkable city, but you can also use:
- Public buses
- Bicycles for rent
- Taxis for longer distances

The historic center is best explored on foot, allowing you to discover hidden piazzas and charming side streets.`;

  const florenceHtml = marked(florenceMarkdown);
  const now = new Date().toISOString();

  const insertPost = db.prepare(`
    INSERT INTO posts (title, slug, body_md, body_html, status, published_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  insertPost.run(
    'Florence Guide',
    'florence',
    florenceMarkdown,
    florenceHtml,
    'published',
    now,
    now
  );

  console.log('Seeded database with Florence post');
}

if (userCount.count === 0) {
  const adminPassword = 'admin123';
  const saltRounds = 10;
  const passwordHash = bcrypt.hashSync(adminPassword, saltRounds);
  const now = new Date().toISOString();

  const insertUser = db.prepare(`
    INSERT INTO users (email, password_hash, created_at)
    VALUES (?, ?, ?)
  `);

  insertUser.run('admin@example.com', passwordHash, now);

  console.log('Seeded database with admin user (admin@example.com / admin123)');
}

export default db;
