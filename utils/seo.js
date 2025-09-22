/**
 * SEO utility functions
 */

/**
 * Generate a clean description from markdown content
 * @param {string} markdown - The markdown content
 * @param {number} maxLength - Maximum length of description (default: 150)
 * @returns {string} Clean description
 */
export function generateDescription(markdown, maxLength = 150) {
  if (!markdown) return '';
  
  // Remove markdown syntax
  let clean = markdown
    .replace(/[#*`]/g, '') // Remove headers, bold, italic, code markers
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // Convert links to text
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, '') // Remove images
    .replace(/\n+/g, ' ') // Replace newlines with spaces
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .trim();
  
  // Truncate to maxLength and add ellipsis if needed
  if (clean.length > maxLength) {
    clean = clean.substring(0, maxLength).trim();
    // Don't cut off mid-word if possible
    const lastSpace = clean.lastIndexOf(' ');
    if (lastSpace > maxLength * 0.8) {
      clean = clean.substring(0, lastSpace);
    }
    clean += '...';
  }
  
  return clean;
}

/**
 * Generate sitemap XML content
 * @param {Array} posts - Array of published posts
 * @param {Array} pages - Array of published pages
 * @param {string} baseUrl - Base URL of the site
 * @returns {string} XML sitemap content
 */
export function generateSitemap(posts, pages = [], baseUrl) {
  const urls = [];
  
  // Add homepage
  urls.push({
    loc: baseUrl,
    lastmod: new Date().toISOString().split('T')[0],
    changefreq: 'daily'
  });
  
  // Add posts
  posts.forEach(post => {
    urls.push({
      loc: `${baseUrl}/destinations/${post.slug}`,
      lastmod: new Date(post.updated_at).toISOString().split('T')[0],
      changefreq: 'weekly'
    });
  });
  
  // Add pages
  pages.forEach(page => {
    urls.push({
      loc: `${baseUrl}/pages/${page.slug}`,
      lastmod: new Date(page.updated_at).toISOString().split('T')[0],
      changefreq: 'monthly'
    });
  });
  
  // Generate XML
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  
  urls.forEach(url => {
    xml += '  <url>\n';
    xml += `    <loc>${url.loc}</loc>\n`;
    xml += `    <lastmod>${url.lastmod}</lastmod>\n`;
    xml += `    <changefreq>${url.changefreq}</changefreq>\n`;
    xml += '  </url>\n';
  });
  
  xml += '</urlset>';
  
  return xml;
}

/**
 * Generate robots.txt content
 * @param {string} baseUrl - Base URL of the site
 * @returns {string} Robots.txt content
 */
export function generateRobotsTxt(baseUrl) {
  return `User-agent: *
Allow: /
Sitemap: ${baseUrl}/sitemap.xml`;
}
