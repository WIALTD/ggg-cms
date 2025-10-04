// NOTE: Authentication temporarily disabled for testing CMS CRUD and styling.
// TODO: Re-enable requireAuth once first-user setup flow is implemented.

import express from 'express';
import bcrypt from 'bcrypt';
import { marked } from 'marked';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import rateLimit from 'express-rate-limit';
import sharp from 'sharp';
import { requireAuth, redirectIfAuthenticated } from '../middleware/auth.js';

const router = express.Router();

// Rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Use local path for both development and production (free tier)
// Note: Uploaded files will be reset on each deployment on free tier
const uploadsPath = path.join(__dirname, '..', 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
  console.log('Created uploads directory:', uploadsPath);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsPath);
  },
  filename: (req, file, cb) => {
    // Sanitize filename and add timestamp prefix
    const timestamp = Date.now();
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const ext = path.extname(sanitizedName);
    const name = path.basename(sanitizedName, ext);
    cb(null, `${timestamp}_${name}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Only allow image files
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only image files (jpg, jpeg, png, gif, webp) are allowed'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Custom render function to use layout
const renderWithLayout = (res, template, data = {}) => {
  res.render(template, data, (err, html) => {
    if (err) throw err;
    res.render('layout', { ...data, body: html, admin: true });
  });
};

// GET /admin/login - Show login form
router.get('/login', redirectIfAuthenticated, (req, res) => {
  // Check if any users exist
  const userCount = req.db.prepare('SELECT COUNT(*) as count FROM users').get();
  const noUsers = userCount.count === 0;
  const { message } = req.query;
  
  renderWithLayout(res, 'admin/login', { 
    title: 'Admin Login',
    noUsers: noUsers,
    message: message
  });
});

// POST /admin/login - Process login (rate limiting temporarily disabled)
router.post('/login', async (req, res) => {
  console.log('Login attempt:', req.body); // Debug log
  const { email, password } = req.body;

  if (!email || !password) {
    console.log('Missing email or password'); // Debug log
    return renderWithLayout(res, 'admin/login', { 
      title: 'Admin Login',
      error: 'Email and password are required' 
    });
  }

  try {
    // Find user by email
    const user = req.db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
    
    if (!user) {
      return renderWithLayout(res, 'admin/login', { 
        title: 'Admin Login',
        error: 'Invalid email or password' 
      });
    }

    // Compare password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      return renderWithLayout(res, 'admin/login', { 
        title: 'Admin Login',
        error: 'Invalid email or password' 
      });
    }

    // Set session
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    
    res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    renderWithLayout(res, 'admin/login', { 
      title: 'Admin Login',
      error: 'An error occurred during login' 
    });
  }
});

// POST /admin/logout - Logout user
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

// TEMPORARY SETUP ROUTE - Remove after first admin user is created
// GET /admin/setup-admin - One-time setup to create first admin user
router.get('/setup-admin', (req, res) => {
  // Check if any users already exist
  const userCount = req.db.prepare('SELECT COUNT(*) as count FROM users').get();
  
  if (userCount.count > 0) {
    return res.status(403).render('layout', {
      body: `
        <div class="container">
          <h1>Setup Already Complete</h1>
          <p>Admin users already exist. This setup route is no longer available.</p>
          <p><a href="/admin/login">Go to Login</a></p>
        </div>
      `,
      title: 'Setup Complete'
    });
  }

  res.render('layout', {
    body: `
      <div class="container">
        <div class="setup-form">
          <h1>🔧 Initial Setup</h1>
          <p>Create your first admin user account.</p>
          
          <form method="POST" action="/admin/setup-admin" class="user-form">
            <div class="form-group">
              <label for="email">Email Address *</label>
              <input type="email" id="email" name="email" value="alexander@globalguidegroup.com" required>
            </div>
            
            <div class="form-group">
              <label for="password">Password *</label>
              <input type="password" id="password" name="password" value="SecurePass123!" required>
            </div>
            
            <button type="submit" class="btn btn-primary">Create Admin User</button>
          </form>
          
          <div class="warning-message">
            <strong>⚠️ Security Note:</strong> This route will be removed after setup. 
            Please change the password after first login!
          </div>
        </div>
      </div>
    `,
    title: 'Initial Setup',
    admin: true
  });
});

// POST /setup-admin - Process first admin user creation
router.post('/setup-admin', async (req, res) => {
  // Check if any users already exist
  const userCount = req.db.prepare('SELECT COUNT(*) as count FROM users').get();
  
  if (userCount.count > 0) {
    return res.status(403).render('layout', {
      body: `
        <div class="container">
          <h1>Setup Already Complete</h1>
          <p>Admin users already exist. This setup route is no longer available.</p>
          <p><a href="/admin/login">Go to Login</a></p>
        </div>
      `,
      title: 'Setup Complete'
    });
  }

  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Email and password are required</div>
          <p><a href="/setup-admin">Try Again</a></p>
        </div>
      `,
      title: 'Setup Error',
      admin: true
    });
  }

  try {
    // Check if email already exists (shouldn't happen, but safety check)
    const existingUser = req.db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    
    if (existingUser) {
      return res.render('layout', {
        body: `
          <div class="container">
            <div class="error-message">User with this email already exists</div>
            <p><a href="/admin/login">Go to Login</a></p>
          </div>
        `,
        title: 'Setup Error',
        admin: true
      });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = bcrypt.hashSync(password, saltRounds);
    const now = new Date().toISOString();

    // Insert new admin user
    const insertUser = req.db.prepare(`
      INSERT INTO users (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `);

    insertUser.run(email, passwordHash, now);

    res.render('layout', {
      body: `
        <div class="container">
          <div class="success-message">
            <h1>✅ Admin User Created Successfully!</h1>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Password:</strong> ${password}</p>
            <p><strong>⚠️ Important:</strong> Please change the password after first login!</p>
          </div>
          <p><a href="/admin/login" class="btn btn-primary">Go to Login</a></p>
        </div>
      `,
      title: 'Setup Complete',
      admin: true
    });

  } catch (error) {
    console.error('Setup error:', error);
    res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Error creating admin user: ${error.message}</div>
          <p><a href="/setup-admin">Try Again</a></p>
        </div>
      `,
      title: 'Setup Error',
      admin: true
    });
  }
});

// TEMPORARY RESET ROUTE - Remove after setup
// GET /admin/reset-db - Reset database (REMOVE AFTER USE)
router.get('/reset-db', (req, res) => {
  try {
    // Delete all users
    req.db.prepare('DELETE FROM users').run();
    
    res.render('layout', {
      body: `
        <div class="container">
          <div class="success-message">
            <h1>✅ Database Reset Complete</h1>
            <p>All users have been deleted. You can now use the setup route.</p>
            <p><a href="/admin/setup-admin" class="btn btn-primary">Go to Setup</a></p>
          </div>
        </div>
      `,
      title: 'Database Reset',
      admin: true
    });
  } catch (error) {
    res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Error resetting database: ${error.message}</div>
        </div>
      `,
      title: 'Reset Error',
      admin: true
    });
  }
});

// TEMPORARY DIAGNOSTIC ROUTE - Remove after setup
// GET /admin/debug - Check database status
router.get('/debug', (req, res) => {
  try {
    const userCount = req.db.prepare('SELECT COUNT(*) as count FROM users').get();
    const postCount = req.db.prepare('SELECT COUNT(*) as count FROM posts').get();
    
    res.render('layout', {
      body: `
        <div class="container">
          <h1>🔍 Database Debug Info</h1>
          <div class="info-box">
            <p><strong>Users in database:</strong> ${userCount.count}</p>
            <p><strong>Posts in database:</strong> ${postCount.count}</p>
            <p><strong>Setup route should work:</strong> ${userCount.count === 0 ? 'YES' : 'NO'}</p>
          </div>
          <p><a href="/admin/reset-db" class="btn btn-primary">Reset Database</a></p>
          <p><a href="/admin/setup-admin" class="btn btn-secondary">Try Setup</a></p>
          <p><a href="/admin/create-admin-now" class="btn btn-success">Create Admin Now (Direct)</a></p>
        </div>
      `,
      title: 'Debug Info',
      admin: true
    });
  } catch (error) {
    res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Database error: ${error.message}</div>
        </div>
      `,
      title: 'Debug Error',
      admin: true
    });
  }
});

// TEMPORARY DIRECT ADMIN CREATION - Remove after setup
// GET /admin/create-admin-now - Directly create admin user
router.get('/create-admin-now', (req, res) => {
  try {
    // Check if users already exist
    const userCount = req.db.prepare('SELECT COUNT(*) as count FROM users').get();
    
    if (userCount.count > 0) {
      return res.render('layout', {
        body: `
          <div class="container">
            <div class="warning-message">
              <h1>Users Already Exist</h1>
              <p>There are already ${userCount.count} users in the database.</p>
              <p><a href="/admin/reset-db" class="btn btn-primary">Reset Database First</a></p>
            </div>
          </div>
        `,
        title: 'Users Exist',
        admin: true
      });
    }

    // Create admin user directly
    const adminEmail = 'alexander@globalguidegroup.com';
    const adminPassword = 'SecurePass123!';
    
    // Check if email already exists
    const existingUser = req.db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
    
    if (existingUser) {
      return res.render('layout', {
        body: `
          <div class="container">
            <div class="error-message">User with this email already exists</div>
            <p><a href="/admin/login" class="btn btn-primary">Go to Login</a></p>
          </div>
        `,
        title: 'User Exists',
        admin: true
      });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = bcrypt.hashSync(adminPassword, saltRounds);
    const now = new Date().toISOString();

    // Insert new admin user
    const insertUser = req.db.prepare(`
      INSERT INTO users (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `);

    insertUser.run(adminEmail, passwordHash, now);

    res.render('layout', {
      body: `
        <div class="container">
          <div class="success-message">
            <h1>✅ Admin User Created Successfully!</h1>
            <p><strong>Email:</strong> ${adminEmail}</p>
            <p><strong>Password:</strong> ${adminPassword}</p>
            <p><strong>⚠️ Important:</strong> Please change the password after first login!</p>
          </div>
          <p><a href="/admin/login" class="btn btn-primary">Go to Login</a></p>
        </div>
      `,
      title: 'Setup Complete',
      admin: true
    });

  } catch (error) {
    console.error('Direct admin creation error:', error);
    res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Error creating admin user: ${error.message}</div>
          <p><a href="/admin/debug" class="btn btn-secondary">Back to Debug</a></p>
        </div>
      `,
      title: 'Setup Error',
      admin: true
    });
  }
});

// TEMPORARY LOGIN TEST - Remove after setup
// GET /admin/test-login - Test login functionality
router.get('/test-login', (req, res) => {
  try {
    const users = req.db.prepare('SELECT email, created_at FROM users').all();
    
    res.render('layout', {
      body: `
        <div class="container">
          <h1>🔍 Login Test</h1>
          <div class="info-box">
            <p><strong>Users in database:</strong> ${users.length}</p>
            ${users.map(user => `
              <p><strong>Email:</strong> ${user.email}</p>
              <p><strong>Created:</strong> ${user.created_at}</p>
            `).join('')}
          </div>
          <p><a href="/admin/login" class="btn btn-primary">Try Login</a></p>
          <p><a href="/admin/debug" class="btn btn-secondary">Back to Debug</a></p>
        </div>
      `,
      title: 'Login Test',
      admin: true
    });
  } catch (error) {
    res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Database error: ${error.message}</div>
        </div>
      `,
      title: 'Test Error',
      admin: true
    });
  }
});

// SIMPLE ADMIN CREATION - Just create and redirect
// GET /create-admin - Simple one-click admin creation
router.get('/create-admin', (req, res) => {
  try {
    // Check if users already exist
    const userCount = req.db.prepare('SELECT COUNT(*) as count FROM users').get();
    
    if (userCount.count > 0) {
      return res.redirect('/admin/login?message=users-exist');
    }

    // Create admin user
    const adminEmail = 'alexander@globalguidegroup.com';
    const adminPassword = 'SecurePass123!';
    
    const saltRounds = 10;
    const passwordHash = bcrypt.hashSync(adminPassword, saltRounds);
    const now = new Date().toISOString();

    const insertUser = req.db.prepare(`
      INSERT INTO users (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `);

    insertUser.run(adminEmail, passwordHash, now);

    // Redirect to login with success message
    res.redirect('/admin/login?message=admin-created');

  } catch (error) {
    console.error('Admin creation error:', error);
    res.redirect('/admin/login?message=error');
  }
});

// SIMPLE LOGIN TEST - Test login without form
// GET /admin/test-login-simple - Test login with hardcoded credentials
router.get('/test-login-simple', async (req, res) => {
  try {
    const email = 'alexander@globalguidegroup.com';
    const password = 'SecurePass123!';
    
    // Find user by email
    const user = req.db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
    
    if (!user) {
      return res.render('layout', {
        body: `
          <div class="container">
            <div class="error-message">User not found: ${email}</div>
            <p><a href="/admin/create-admin" class="btn btn-primary">Create Admin User</a></p>
          </div>
        `,
        title: 'Login Test - User Not Found',
        admin: true
      });
    }

    // Compare password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      return res.render('layout', {
        body: `
          <div class="container">
            <div class="error-message">Invalid password for: ${email}</div>
            <p><a href="/admin/create-admin" class="btn btn-primary">Recreate Admin User</a></p>
          </div>
        `,
        title: 'Login Test - Invalid Password',
        admin: true
      });
    }

    // Set session
    req.session.userId = user.id;
    req.session.userEmail = user.email;

    res.render('layout', {
      body: `
        <div class="container">
          <div class="success-message">
            <h1>✅ Login Test Successful!</h1>
            <p>User: ${user.email}</p>
            <p>Session ID: ${req.session.userId}</p>
          </div>
          <p><a href="/admin/dashboard" class="btn btn-primary">Go to Dashboard</a></p>
        </div>
      `,
      title: 'Login Test - Success',
      admin: true
    });

  } catch (error) {
    console.error('Login test error:', error);
    res.render('layout', {
      body: `
        <div class="container">
          <div class="error-message">Login test error: ${error.message}</div>
        </div>
      `,
      title: 'Login Test - Error',
      admin: true
    });
  }
});

// GET /admin/dashboard - Protected admin dashboard
// router.get('/dashboard', requireAuth, (req, res) => {
router.get('/dashboard', (req, res) => {
  const { success } = req.query;
  renderWithLayout(res, 'admin/dashboard', { 
    title: 'Admin Dashboard',
    userEmail: req.session.userEmail,
    success: success
  });
});

// Admin Posts CRUD routes

// GET /admin/posts - List all posts
// router.get('/posts', requireAuth, (req, res) => {
router.get('/posts', (req, res) => {
  const posts = req.db.prepare(`
    SELECT id, title, slug, status, featured_image, published_at, updated_at
    FROM posts 
    ORDER BY updated_at DESC
  `).all();

  renderWithLayout(res, 'admin/posts', { 
    title: 'Manage Posts',
    posts 
  });
});

// GET /admin/posts/new - Show create post form
// router.get('/posts/new', requireAuth, (req, res) => {
router.get('/posts/new', (req, res) => {
  renderWithLayout(res, 'admin/post_form', { 
    title: 'Create New Post',
    post: null,
    action: 'create'
  });
});

// POST /admin/posts - Create new post
// router.post('/posts', requireAuth, (req, res) => {
router.post('/posts', (req, res) => {
  const { title, slug, body_md, status, featured_image } = req.body;

  if (!title || !slug || !body_md) {
    return renderWithLayout(res, 'admin/post_form', { 
      title: 'Create New Post',
      post: { title, slug, body_md, status: status || 'draft', featured_image },
      action: 'create',
      error: 'Title, slug, and content are required' 
    });
  }

  try {
    // Convert markdown to HTML
    const body_html = marked.parse(body_md);
    
    // Set published_at if status is published
    const published_at = status === 'published' ? new Date().toISOString() : null;
    const now = new Date().toISOString();

    const insertPost = req.db.prepare(`
      INSERT INTO posts (title, slug, body_md, body_html, status, featured_image, published_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertPost.run(title, slug, body_md, body_html, status || 'draft', featured_image || null, published_at, now);

    res.redirect('/admin/posts');
  } catch (error) {
    console.error('Error creating post:', error);
    renderWithLayout(res, 'admin/post_form', { 
      title: 'Create New Post',
      post: { title, slug, body_md, status: status || 'draft', featured_image },
      action: 'create',
      error: 'Error creating post. Slug may already exist.' 
    });
  }
});

// GET /admin/posts/:id/edit - Show edit post form
// router.get('/posts/:id/edit', requireAuth, (req, res) => {
router.get('/posts/:id/edit', (req, res) => {
  const { id } = req.params;
  
  const post = req.db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
  
  if (!post) {
    return res.status(404).render('layout', { 
      body: `<div class="container"><h1>404 - Post not found</h1><p>The requested post could not be found.</p></div>`,
      title: '404'
    });
  }

  renderWithLayout(res, 'admin/post_form', { 
    title: 'Edit Post',
    post,
    action: 'edit'
  });
});

// POST /admin/posts/:id - Update existing post
// router.post('/posts/:id', requireAuth, (req, res) => {
router.post('/posts/:id', (req, res) => {
  const { id } = req.params;
  const { title, slug, body_md, status, featured_image } = req.body;

  if (!title || !slug || !body_md) {
    return renderWithLayout(res, 'admin/post_form', { 
      title: 'Edit Post',
      post: { id, title, slug, body_md, status: status || 'draft', featured_image },
      action: 'edit',
      error: 'Title, slug, and content are required' 
    });
  }

  try {
    // Convert markdown to HTML
    const body_html = marked.parse(body_md);
    
    // Get existing post to check current status
    const existingPost = req.db.prepare('SELECT status, published_at FROM posts WHERE id = ?').get(id);
    
    // Set published_at if status changed to published and wasn't published before
    let published_at = existingPost.published_at;
    if (status === 'published' && existingPost.status !== 'published') {
      published_at = new Date().toISOString();
    } else if (status === 'draft') {
      published_at = null;
    }
    
    const now = new Date().toISOString();

    const updatePost = req.db.prepare(`
      UPDATE posts 
      SET title = ?, slug = ?, body_md = ?, body_html = ?, status = ?, featured_image = ?, published_at = ?, updated_at = ?
      WHERE id = ?
    `);

    updatePost.run(title, slug, body_md, body_html, status, featured_image || null, published_at, now, id);

    res.redirect('/admin/posts');
  } catch (error) {
    console.error('Error updating post:', error);
    renderWithLayout(res, 'admin/post_form', { 
      title: 'Edit Post',
      post: { id, title, slug, body_md, status: status || 'draft', featured_image },
      action: 'edit',
      error: 'Error updating post. Slug may already exist.' 
    });
  }
});

// POST /admin/posts/:id/delete - Delete post
// router.post('/posts/:id/delete', requireAuth, (req, res) => {
router.post('/posts/:id/delete', (req, res) => {
  const { id } = req.params;
  
  try {
    const deletePost = req.db.prepare('DELETE FROM posts WHERE id = ?');
    const result = deletePost.run(id);
    
    if (result.changes === 0) {
      return res.status(404).render('layout', { 
        body: `<div class="container"><h1>404 - Post not found</h1><p>The requested post could not be found.</p></div>`,
        title: '404'
      });
    }

    res.redirect('/admin/posts');
  } catch (error) {
    console.error('Error deleting post:', error);
    res.redirect('/admin/posts');
  }
});

// File Upload routes

// GET /admin/upload - Show upload form
// router.get('/upload', requireAuth, (req, res) => {
router.get('/upload', (req, res) => {
  // Debug: Check if uploads directory exists
  const uploadsExists = fs.existsSync(uploadsPath);
  console.log('Uploads directory path:', uploadsPath);
  console.log('Uploads directory exists:', uploadsExists);
  
  renderWithLayout(res, 'admin/upload', { 
    title: 'Upload Image',
    message: null,
    fileUrl: null,
    debug: {
      uploadsPath: uploadsPath,
      uploadsExists: uploadsExists
    }
  });
});

// POST /admin/upload - Handle file upload
// router.post('/upload', requireAuth, upload.single('image'), (req, res) => {
router.post('/upload', upload.single('image'), (req, res) => {
  console.log('Upload attempt:', req.body); // Debug log
  console.log('Upload file:', req.file); // Debug log
  
  try {
    if (!req.file) {
      console.log('No file received'); // Debug log
      return renderWithLayout(res, 'admin/upload', { 
        title: 'Upload Image',
        message: 'No file selected or file upload failed',
        fileUrl: null
      });
    }

    console.log('File uploaded successfully:', req.file.filename); // Debug log
    const fileUrl = `/uploads/${req.file.filename}`;
    
    renderWithLayout(res, 'admin/upload', { 
      title: 'Upload Image',
      message: 'File uploaded successfully!',
      fileUrl: fileUrl,
      fileName: req.file.originalname
    });
  } catch (error) {
    console.error('Upload error:', error);
    renderWithLayout(res, 'admin/upload', { 
      title: 'Upload Image',
      message: error.message || 'Error uploading file',
      fileUrl: null
    });
  }
});

// User Management routes

// GET /admin/users/new - Show create user form
// router.get('/users/new', requireAuth, (req, res) => {
router.get('/users/new', (req, res) => {
  renderWithLayout(res, 'admin/user_form', {
    title: 'Create New User',
    user: null,
    action: 'create'
  });
});

// POST /admin/users - Create new user
// router.post('/users', requireAuth, (req, res) => {
router.post('/users', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return renderWithLayout(res, 'admin/user_form', {
      title: 'Create New User',
      user: { email, password: '' },
      action: 'create',
      error: 'Email and password are required'
    });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return renderWithLayout(res, 'admin/user_form', {
      title: 'Create New User',
      user: { email, password: '' },
      action: 'create',
      error: 'Please enter a valid email address'
    });
  }

  // Validate password length
  if (password.length < 6) {
    return renderWithLayout(res, 'admin/user_form', {
      title: 'Create New User',
      user: { email, password: '' },
      action: 'create',
      error: 'Password must be at least 6 characters long'
    });
  }

  try {
    // Check if email already exists
    const existingUser = req.db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    
    if (existingUser) {
      return renderWithLayout(res, 'admin/user_form', {
        title: 'Create New User',
        user: { email, password: '' },
        action: 'create',
        error: 'A user with this email already exists'
      });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = bcrypt.hashSync(password, saltRounds);
    const now = new Date().toISOString();

    // Insert new user
    const insertUser = req.db.prepare(`
      INSERT INTO users (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `);

    insertUser.run(email, passwordHash, now);

    // Redirect to dashboard with success message
    res.redirect('/admin/dashboard?success=user_created');
  } catch (error) {
    console.error('Error creating user:', error);
    renderWithLayout(res, 'admin/user_form', {
      title: 'Create New User',
      user: { email, password: '' },
      action: 'create',
      error: 'Error creating user. Please try again.'
    });
  }
});

// Media Library routes

// GET /admin/media - Media library interface
// router.get('/media', requireAuth, (req, res) => {
router.get('/media', (req, res) => {
  const { folder } = req.query;
  const currentFolder = folder || '';
  
  // Get all media files, optionally filtered by folder
  let mediaQuery = 'SELECT * FROM media';
  let params = [];
  
  if (currentFolder) {
    mediaQuery += ' WHERE folder = ?';
    params.push(currentFolder);
  }
  
  mediaQuery += ' ORDER BY uploaded_at DESC';
  
  const media = req.db.prepare(mediaQuery).all(...params);
  
  // Get all unique folders
  const folders = req.db.prepare('SELECT DISTINCT folder FROM media WHERE folder != "" ORDER BY folder').all();
  
  renderWithLayout(res, 'admin/media', {
    title: 'Media Library',
    media,
    folders,
    currentFolder
  });
});

// POST /admin/media/upload - Handle drag-and-drop upload
// router.post('/media/upload', requireAuth, upload.array('files', 10), async (req, res) => {
router.post('/media/upload', upload.array('files', 10), async (req, res) => {
  try {
    const { folder = '' } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }
    
    const uploadedFiles = [];
    
    for (const file of files) {
      // Generate thumbnail for images
      let thumbnailPath = null;
      if (file.mimetype.startsWith('image/')) {
        const thumbnailFilename = `thumb_${file.filename}`;
        const thumbnailFullPath = path.join(uploadsPath, thumbnailFilename);
        
        try {
          await sharp(file.path)
            .resize(300, 300, { fit: 'inside', withoutEnlargement: true })
            .jpeg({ quality: 80 })
            .toFile(thumbnailFullPath);
          
          thumbnailPath = `/uploads/${thumbnailFilename}`;
        } catch (sharpError) {
          console.error('Thumbnail generation failed:', sharpError);
        }
      }
      
      // Store file info in database
      const insertMedia = req.db.prepare(`
        INSERT INTO media (filename, original_name, file_path, file_size, mime_type, folder, thumbnail_path, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      const now = new Date().toISOString();
      insertMedia.run(
        file.filename,
        file.originalname,
        `/uploads/${file.filename}`,
        file.size,
        file.mimetype,
        folder,
        thumbnailPath,
        now
      );
      
      uploadedFiles.push({
        id: req.db.prepare('SELECT last_insert_rowid() as id').get().id,
        filename: file.filename,
        original_name: file.originalname,
        file_path: `/uploads/${file.filename}`,
        file_size: file.size,
        mime_type: file.mimetype,
        folder,
        thumbnail_path: thumbnailPath,
        uploaded_at: now
      });
    }
    
    res.json({ success: true, files: uploadedFiles });
  } catch (error) {
    console.error('Media upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// POST /admin/media/delete/:id - Delete media file
// router.post('/media/delete/:id', requireAuth, (req, res) => {
router.post('/media/delete/:id', (req, res) => {
  const { id } = req.params;
  
  try {
    // Get file info before deleting
    const mediaFile = req.db.prepare('SELECT * FROM media WHERE id = ?').get(id);
    
    if (!mediaFile) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Delete physical files
    const filePath = path.join(__dirname, '..', 'uploads', mediaFile.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    
    if (mediaFile.thumbnail_path) {
      const thumbnailFilename = path.basename(mediaFile.thumbnail_path);
      const thumbnailPath = path.join(__dirname, '..', 'uploads', thumbnailFilename);
      if (fs.existsSync(thumbnailPath)) {
        fs.unlinkSync(thumbnailPath);
      }
    }
    
    // Delete from database
    const deleteMedia = req.db.prepare('DELETE FROM media WHERE id = ?');
    deleteMedia.run(id);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Media delete error:', error);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// POST /admin/media/folder - Create new folder
// router.post('/media/folder', requireAuth, (req, res) => {
router.post('/media/folder', (req, res) => {
  const { folderName } = req.body;
  
  if (!folderName || folderName.trim() === '') {
    return res.status(400).json({ error: 'Folder name is required' });
  }
  
  // For now, folders are just metadata in the database
  // Physical folder creation could be added if needed
  res.json({ success: true, folderName: folderName.trim() });
});

// POST /admin/media/rename/:id - Rename media file
// router.post('/media/rename/:id', requireAuth, (req, res) => {
router.post('/media/rename/:id', (req, res) => {
  const { id } = req.params;
  const { newName } = req.body;
  
  if (!newName || newName.trim() === '') {
    return res.status(400).json({ error: 'New name is required' });
  }
  
  try {
    const updateMedia = req.db.prepare('UPDATE media SET original_name = ?, updated_at = ? WHERE id = ?');
    const now = new Date().toISOString();
    updateMedia.run(newName.trim(), now, id);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Media rename error:', error);
    res.status(500).json({ error: 'Rename failed' });
  }
});

// Error handling middleware for multer
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return renderWithLayout(res, 'admin/upload', { 
        title: 'Upload Image',
        message: 'File too large. Maximum size is 5MB.',
        fileUrl: null
      });
    }
  }
  
  if (error.message.includes('Only image files')) {
    return renderWithLayout(res, 'admin/upload', { 
      title: 'Upload Image',
      message: 'Only image files (jpg, jpeg, png, gif, webp) are allowed.',
      fileUrl: null
    });
  }
  
  next(error);
});

export default router;
