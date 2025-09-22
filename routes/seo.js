import express from 'express';
import { generateSitemap, generateRobotsTxt } from '../utils/seo.js';

const router = express.Router();

// GET /sitemap.xml - Generate sitemap
router.get('/sitemap.xml', (req, res) => {
  try {
    const posts = req.db.prepare(`
      SELECT slug, updated_at
      FROM posts 
      WHERE status = 'published' 
      ORDER BY updated_at DESC
    `).all();

    const pages = req.db.prepare(`
      SELECT slug, updated_at
      FROM pages 
      WHERE status = 'published' 
      ORDER BY updated_at DESC
    `).all();

    const sitemap = generateSitemap(posts, pages, req.baseUrl);
    
    res.set('Content-Type', 'application/xml');
    res.send(sitemap);
  } catch (error) {
    console.error('Error generating sitemap:', error);
    res.status(500).send('Error generating sitemap');
  }
});

// GET /robots.txt - Generate robots.txt
router.get('/robots.txt', (req, res) => {
  try {
    const robotsTxt = generateRobotsTxt(req.baseUrl);
    
    res.set('Content-Type', 'text/plain');
    res.send(robotsTxt);
  } catch (error) {
    console.error('Error generating robots.txt:', error);
    res.status(500).send('Error generating robots.txt');
  }
});

export default router;
