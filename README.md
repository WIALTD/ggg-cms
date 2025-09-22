# GGG CMS - Hybrid Content Management System

A simple hybrid CMS built with Node.js + Express + SQLite that serves both HTML pages and JSON API endpoints.

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: SQLite with better-sqlite3
- **Templates**: EJS
- **Styling**: Custom CSS with system fonts
- **Authentication**: Express-session with bcrypt
- **Markdown**: Marked library for markdown processing
- **File Uploads**: Multer with image validation
- **Security**: Helmet, rate limiting, input validation

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Visit the site
open http://localhost:3000
```

## Project Structure

```
ggg-cms/
├── server.js              # Main Express server (118 lines)
├── db.js                  # Database initialization and seeding
├── middleware/
│   └── auth.js            # Authentication middleware
├── routes/
│   ├── public.js          # Public routes (/, /destinations/:slug)
│   ├── admin.js           # Admin routes (/admin/*)
│   ├── api.js             # API routes (/api/*)
│   └── seo.js             # SEO routes (/sitemap.xml, /robots.txt)
├── utils/
│   └── seo.js             # SEO utilities
├── views/
│   ├── layout.ejs         # Main layout template
│   ├── index.ejs          # Home page (posts list)
│   ├── post.ejs           # Single post view
│   └── admin/
│       ├── login.ejs      # Admin login form
│       ├── dashboard.ejs  # Admin dashboard
│       ├── posts.ejs      # Admin posts list
│       ├── post_form.ejs  # Admin post create/edit form
│       └── upload.ejs     # Admin file upload
├── public/
│   ├── css/
│   │   ├── base.css       # Resets, typography, colors (113 lines)
│   │   ├── layout.css     # Header, footer, nav, container (105 lines)
│   │   ├── prose.css      # Article/post-specific styling (112 lines)
│   │   └── admin.css      # Admin dashboard, forms, tables (535 lines)
│   └── images/
│       └── default-og.jpg # Default Open Graph image
└── uploads/               # User uploaded files
```

## CSS Style Guide

The CSS is organized into modular files for maintainability and performance:

### CSS Loading Pattern

- **Public pages** load: `base.css` + `layout.css`
- **Post pages** load: `base.css` + `layout.css` + `prose.css`
- **Admin pages** load: `base.css` + `layout.css` + `admin.css`

### File Organization

- **`base.css`** - Reset styles, typography, colors, links, utility classes
- **`layout.css`** - Header, footer, navigation, container, responsive grid
- **`prose.css`** - Single post styling, markdown rendering, content typography
- **`admin.css`** - Admin forms, dashboard, tables, buttons, file upload interface

### Template Implementation

```ejs
<!-- All pages -->
<link rel="stylesheet" href="/css/base.css">
<link rel="stylesheet" href="/css/layout.css">

<!-- Post pages only -->
<link rel="stylesheet" href="/css/prose.css">

<!-- Admin pages only -->
<% if (typeof admin !== 'undefined' && admin) { %>
<link rel="stylesheet" href="/css/admin.css">
<% } %>
```

## Features

### ✅ Content Management
- Create, edit, delete posts with Markdown editor
- Draft/published status management
- Featured images for social sharing
- File upload with image validation

### ✅ Authentication & Security
- Admin login with bcrypt password hashing
- Session management with secure cookies
- Rate limiting on login attempts
- Input validation and sanitization
- Helmet security headers

### ✅ SEO & Social Sharing
- Open Graph and Twitter Card meta tags
- Dynamic sitemap.xml generation
- Robots.txt with sitemap reference
- Canonical URLs and meta descriptions
- Featured images for social previews

### ✅ API Endpoints
- JSON API for all published posts
- Individual post JSON endpoints
- Headless CMS capabilities

### ✅ File Management
- Image upload with type/size validation
- Sanitized filenames with timestamps
- Static file serving for uploads

## Routes

### Public Routes
- `GET /` - Home page (list published posts)
- `GET /destinations/:slug` - Single post page
- `GET /api/posts` - All published posts (JSON)
- `GET /api/posts/:slug` - Single post (JSON)
- `GET /sitemap.xml` - Dynamic sitemap
- `GET /robots.txt` - Robots.txt
- `GET /health` - Health check endpoint

### Admin Routes
- `GET /admin/login` - Admin login form
- `POST /admin/login` - Process login (rate limited)
- `POST /admin/logout` - Logout
- `GET /admin/dashboard` - Admin dashboard (protected)
- `GET /admin/posts` - List all posts (protected)
- `GET /admin/posts/new` - Create new post form (protected)
- `POST /admin/posts` - Create new post (protected)
- `GET /admin/posts/:id/edit` - Edit post form (protected)
- `POST /admin/posts/:id` - Update post (protected)
- `POST /admin/posts/:id/delete` - Delete post (protected)
- `GET /admin/upload` - Upload form (protected)
- `POST /admin/upload` - Handle file upload (protected)

## Database Schema

### Posts Table
- `id` (INTEGER PRIMARY KEY)
- `title` (TEXT NOT NULL)
- `slug` (TEXT UNIQUE NOT NULL)
- `body_md` (TEXT NOT NULL) - Markdown content
- `body_html` (TEXT NOT NULL) - Rendered HTML
- `status` (TEXT DEFAULT 'draft') - 'draft' or 'published'
- `featured_image` (TEXT) - URL for social sharing
- `published_at` (DATETIME)
- `updated_at` (DATETIME DEFAULT CURRENT_TIMESTAMP)

### Users Table
- `id` (INTEGER PRIMARY KEY)
- `email` (TEXT UNIQUE NOT NULL)
- `password_hash` (TEXT NOT NULL)
- `created_at` (DATETIME DEFAULT CURRENT_TIMESTAMP)

## Development

### Default Credentials
- **Email**: admin@example.com
- **Password**: admin123

### Environment Variables
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)
- `SESSION_SECRET` - Session secret key

### File Uploads
- **Location**: `/uploads/` directory
- **Types**: Images only (jpg, jpeg, png, gif, webp)
- **Size limit**: 5MB per file
- **Naming**: Timestamp + sanitized original name

## Deployment

The application is designed to run on any Node.js hosting platform:

- **Render**: Deploy directly from Git
- **Railway**: One-click deployment
- **VPS**: Standard Node.js deployment

### Production Checklist
- [ ] Set `SESSION_SECRET` environment variable
- [ ] Set `NODE_ENV=production`
- [ ] Use HTTPS for secure cookies
- [ ] Configure file upload limits
- [ ] Set up database backups

## Security Features

- **Password Hashing**: bcrypt with salt rounds
- **Session Security**: httpOnly, secure cookies
- **Rate Limiting**: Login attempt protection
- **Input Validation**: All user inputs sanitized
- **File Upload Security**: Type and size validation
- **SQL Injection Protection**: Parameterized queries
- **HTTP Headers**: Helmet middleware
- **Error Handling**: Production-safe error responses

## Contributing

When adding new templates or modifying existing ones:

1. **Follow CSS loading pattern**:
   - Public pages: `base.css` + `layout.css`
   - Post pages: + `prose.css`
   - Admin pages: + `admin.css`

2. **Use semantic HTML** elements where possible
3. **Follow existing code style** and patterns
4. **Test all routes** after changes
5. **Update documentation** if adding new features

## License

ISC
