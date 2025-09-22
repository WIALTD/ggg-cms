# GGG CMS Deployment Guide

## Render Deployment

### Prerequisites
- GitHub repository with the GGG CMS code
- Render account (free tier available)

### Environment Variables

Set these in your Render dashboard:

#### Required Variables
```
SESSION_SECRET=your-secure-production-secret-key
NODE_ENV=production
BASE_URL=https://next.globalguidegroup.com
```

#### Optional Variables
```
PORT=3000
```

### Render Configuration

1. **Service Type**: Web Service
2. **Environment**: Node.js
3. **Build Command**: `npm install`
4. **Start Command**: `npm start`
5. **Health Check Path**: `/health`

### Storage (Free Tier Limitations)

**Note**: The free tier on Render does not support persistent storage. This means:
- Database and uploaded files will be reset on each deployment
- This is fine for demo/testing purposes
- For production with persistent data, upgrade to a paid plan

**Current Setup**:
- SQLite database: `./content.sqlite` (local filesystem)
- Uploaded files: `./uploads/` (local filesystem)

### Custom Domain

1. In Render dashboard, go to your service settings
2. Add custom domain: `next.globalguidegroup.com`
3. Render will automatically configure HTTPS

### Testing After Deployment

Visit these URLs to verify deployment:

- ✅ `https://next.globalguidegroup.com/` - Homepage
- ✅ `https://next.globalguidegroup.com/destinations/florence` - Florence guide
- ✅ `https://next.globalguidegroup.com/api/posts` - JSON API
- ✅ `https://next.globalguidegroup.com/admin/login` - Admin login
- ✅ `https://next.globalguidegroup.com/sitemap.xml` - Sitemap
- ✅ `https://next.globalguidegroup.com/robots.txt` - Robots.txt
- ✅ `https://next.globalguidegroup.com/health` - Health check

### Default Admin Credentials

- **Email**: admin@example.com
- **Password**: admin123

**⚠️ Important**: Change these credentials after first login in production!

### Troubleshooting

#### Database Issues
- Ensure persistent volume is mounted at `/data`
- Check that SQLite database is created in `/data/content.sqlite`

#### File Upload Issues
- Verify uploads directory exists at `/data/uploads`
- Check file permissions

#### Environment Variables
- Ensure all required environment variables are set
- Verify `BASE_URL` matches your custom domain

### Performance Optimization

#### Future Improvements
- Add compression middleware (gzip)
- Add logging middleware (morgan)
- Consider Cloudflare for caching and DDoS protection
- Implement Redis for session storage (optional)

### Security Notes

- Session secret should be a strong, random string
- Use HTTPS in production (automatically configured by Render)
- Consider implementing additional rate limiting
- Regular security updates for dependencies
