import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import db from './db.js';

// Import route modules
import publicRoutes from './routes/public.js';
import adminRoutes from './routes/admin.js';
import apiRoutes from './routes/api.js';
import seoRoutes from './routes/seo.js';

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const isProduction = process.env.NODE_ENV === 'production';

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Set EJS as the template engine
app.set('view engine', 'ejs');
app.set('views', './views');

// Serve static files from public directory
app.use(express.static('public'));

// Serve uploaded files from uploads directory
// Note: Uploaded files will be reset on each deployment on free tier
const uploadsPath = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(uploadsPath));

// Parse JSON bodies
app.use(express.json());

// Parse URL-encoded bodies (for form data)
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction, // Set to true in production with HTTPS
    httpOnly: true, // Prevent XSS attacks
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Middleware to add database and BASE_URL to request object
app.use((req, res, next) => {
  req.db = db;
  req.baseUrl = BASE_URL;
  next();
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

// EMERGENCY ADMIN CREATION - Direct route in server.js
app.get('/create-admin-emergency', async (req, res) => {
  try {
    // Check if users already exist
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    
    if (userCount.count > 0) {
      return res.send(`
        <h1>Admin Already Exists</h1>
        <p>There are already ${userCount.count} users in the database.</p>
        <p><a href="/admin/login">Go to Login</a></p>
      `);
    }

    // Create admin user
    const adminEmail = 'alexander@globalguidegroup.com';
    const adminPassword = 'SecurePass123!';
    
    const bcrypt = (await import('bcrypt')).default;
    const saltRounds = 10;
    const passwordHash = bcrypt.hashSync(adminPassword, saltRounds);
    const now = new Date().toISOString();

    const insertUser = db.prepare(`
      INSERT INTO users (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `);

    insertUser.run(adminEmail, passwordHash, now);

    res.send(`
      <h1>✅ Admin User Created!</h1>
      <p><strong>Email:</strong> ${adminEmail}</p>
      <p><strong>Password:</strong> ${adminPassword}</p>
      <p><a href="/admin/login">Go to Login</a></p>
    `);

  } catch (error) {
    console.error('Emergency admin creation error:', error);
    res.send(`
      <h1>❌ Error</h1>
      <p>Error creating admin user: ${error.message}</p>
    `);
  }
});

// EMERGENCY LOGIN TEST - Direct route in server.js
app.get('/test-login-emergency', async (req, res) => {
  try {
    const email = 'alexander@globalguidegroup.com';
    const password = 'SecurePass123!';
    
    // Find user by email
    const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
    
    if (!user) {
      return res.send(`
        <h1>❌ User Not Found</h1>
        <p>User not found: ${email}</p>
        <p><a href="/create-admin-emergency">Create Admin User</a></p>
      `);
    }

    // Compare password
    const bcrypt = (await import('bcrypt')).default;
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      return res.send(`
        <h1>❌ Invalid Password</h1>
        <p>Invalid password for: ${email}</p>
        <p><a href="/create-admin-emergency">Recreate Admin User</a></p>
      `);
    }

    // Set session
    req.session.userId = user.id;
    req.session.userEmail = user.email;

    res.send(`
      <h1>✅ Login Test Successful!</h1>
      <p>User: ${user.email}</p>
      <p>Session ID: ${req.session.userId}</p>
      <p><a href="/admin/dashboard">Go to Dashboard</a></p>
    `);

  } catch (error) {
    console.error('Login test error:', error);
    res.send(`
      <h1>❌ Error</h1>
      <p>Login test error: ${error.message}</p>
    `);
  }
});

// Mount route modules
app.use('/', publicRoutes);
app.use('/api', apiRoutes);
app.use('/admin', adminRoutes);
app.use('/', seoRoutes);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  if (isProduction) {
    res.status(500).render('layout', { 
      body: `<div class="container"><h1>500 - Internal Server Error</h1><p>Something went wrong. Please try again later.</p></div>`,
      title: '500'
    });
  } else {
    res.status(500).render('layout', { 
      body: `<div class="container"><h1>500 - Internal Server Error</h1><p>${error.message}</p><pre>${error.stack}</pre></div>`,
      title: '500'
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('layout', { 
    body: `<div class="container"><h1>404 - Page not found</h1><p>The requested page could not be found.</p></div>`,
    title: '404'
  });
});

// Start server
app.listen(PORT, () => {
  if (!isProduction) {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Visit http://localhost:${PORT}/destinations/florence for the Florence guide`);
    console.log(`Visit http://localhost:${PORT}/api/posts/florence for JSON data`);
  }
});