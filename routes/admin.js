import express from 'express';
import bcrypt from 'bcrypt';
import { marked } from 'marked';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
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

// Use persistent storage path in production, local path in development
const isProduction = process.env.NODE_ENV === 'production';
const uploadsPath = isProduction ? '/data/uploads' : path.join(__dirname, '..', 'uploads');

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
  renderWithLayout(res, 'admin/login', { title: 'Admin Login' });
});

// POST /admin/login - Process login (with rate limiting)
router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
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

// GET /admin/dashboard - Protected admin dashboard
router.get('/dashboard', requireAuth, (req, res) => {
  renderWithLayout(res, 'admin/dashboard', { 
    title: 'Admin Dashboard',
    userEmail: req.session.userEmail 
  });
});

// Admin Posts CRUD routes

// GET /admin/posts - List all posts
router.get('/posts', requireAuth, (req, res) => {
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
router.get('/posts/new', requireAuth, (req, res) => {
  renderWithLayout(res, 'admin/post_form', { 
    title: 'Create New Post',
    post: null,
    action: 'create'
  });
});

// POST /admin/posts - Create new post
router.post('/posts', requireAuth, (req, res) => {
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
router.get('/posts/:id/edit', requireAuth, (req, res) => {
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
router.post('/posts/:id', requireAuth, (req, res) => {
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
router.post('/posts/:id/delete', requireAuth, (req, res) => {
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
router.get('/upload', requireAuth, (req, res) => {
  renderWithLayout(res, 'admin/upload', { 
    title: 'Upload Image',
    message: null,
    fileUrl: null
  });
});

// POST /admin/upload - Handle file upload
router.post('/upload', requireAuth, upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      return renderWithLayout(res, 'admin/upload', { 
        title: 'Upload Image',
        message: 'No file selected',
        fileUrl: null
      });
    }

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
