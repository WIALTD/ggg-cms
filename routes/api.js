import express from 'express';

const router = express.Router();

// API: Get all published posts
router.get('/posts', (req, res) => {
  const posts = req.db.prepare(`
    SELECT id, title, slug, published_at, updated_at
    FROM posts 
    WHERE status = 'published' 
    ORDER BY published_at DESC
  `).all();

  res.json(posts);
});

// API: Get single post
router.get('/posts/:slug', (req, res) => {
  const { slug } = req.params;
  
  const post = req.db.prepare(`
    SELECT id, title, slug, body_md, body_html, featured_image, published_at, updated_at
    FROM posts 
    WHERE slug = ? AND status = 'published'
  `).get(slug);

  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }

  res.json(post);
});

export default router;
