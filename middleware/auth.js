// Middleware to require authentication
export const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    // User is authenticated, proceed to the next middleware/route
    next();
  } else {
    // User is not authenticated, redirect to login page
    res.redirect('/admin/login');
  }
};

// Middleware to redirect authenticated users away from login page
export const redirectIfAuthenticated = (req, res, next) => {
  if (req.session && req.session.userId) {
    // User is already authenticated, redirect to dashboard
    res.redirect('/admin/dashboard');
  } else {
    // User is not authenticated, proceed to login page
    next();
  }
};
