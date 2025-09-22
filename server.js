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
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

// Middleware to add database to request object
app.use((req, res, next) => {
  req.db = db;
  next();
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
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