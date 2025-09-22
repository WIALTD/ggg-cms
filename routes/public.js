import express from 'express';
import { generateDescription } from '../utils/seo.js';

const router = express.Router();

// Custom render function to use layout
const renderWithLayout = (res, template, data = {}) => {
  res.render(template, data, (err, html) => {
    if (err) throw err;
    res.render('layout', { ...data, body: html, admin: false });
  });
};

// Home page - list published posts
router.get('/', (req, res) => {
  const posts = req.db.prepare(`
    SELECT id, title, slug, published_at, updated_at
    FROM posts 
    WHERE status = 'published' 
    ORDER BY published_at DESC
  `).all();

  renderWithLayout(res, 'index', { posts, title: 'Home' });
});

// Single post page
router.get('/destinations/:slug', (req, res) => {
  const { slug } = req.params;
  
  const post = req.db.prepare(`
    SELECT title, slug, body_md, body_html, featured_image, published_at, updated_at
    FROM posts 
    WHERE slug = ? AND status = 'published'
  `).get(slug);

  if (!post) {
    return res.status(404).render('layout', { 
      body: `<div class="container"><h1>404 - Post not found</h1><p>The requested post could not be found.</p></div>`,
      title: '404'
    });
  }

  const description = generateDescription(post.body_md);
  res.render('post', { post, baseUrl: req.protocol + '://' + req.get('host'), description });
});

export default router;
