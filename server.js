// server.js
// Minimal secure Express server demonstrating common website security controls.
// Dependencies: express, helmet, express-rate-limit, cors, dotenv, bcrypt, jsonwebtoken,
// pg (node-postgres), csurf, cookie-parser, express-validator

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- DB pool (use environment variables) ----
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://user:pass@localhost:5432/mydb',
  // ssl: { rejectUnauthorized: false } // enable when connecting to some hosted DBs
});

// ---- Middlewares ----
app.use(express.json());
app.use(cookieParser());

// 1) Security headers with Helmet (CSP set intentionally strict example)
app.use(
  helmet({
    // You can fine-tune directives as needed
  })
);
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

// 2) CORS: restrict origins in production
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',');
app.use(
  cors({
    origin: function (origin, cb) {
      // allow no-origin (non-browser clients like curl/postman)
      if (!origin) return cb(null, true);
      if (allowedOrigins.indexOf(origin) !== -1) return cb(null, true);
      cb(new Error('CORS not allowed'));
    },
    credentials: true,
  })
);

// 3) Rate limiting to prevent brute-force & API abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // adjust; smaller for sensitive endpoints like /login
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// extra stricter limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: 'Too many login attempts, try again later.',
});
app.use('/api/auth/', authLimiter);

// 4) Force HTTPS (basic) - should be handled by reverse proxy in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// 5) CSRF protection using cookies (double-submit cookie pattern)
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
});

// helper: sign JWTs
const signAccessToken = (userId) =>
  jwt.sign({ sub: userId }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
const signRefreshToken = (userId) =>
  jwt.sign({ sub: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

// ---- Routes ----

// simple route to get CSRF token for SPA (call before POST forms)
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false, // readable by JS to send as header
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  });
  res.json({ ok: true });
});

// Register (signup) - validate and hash password, parameterized query
app.post(
  '/api/auth/register',
  csrfProtection,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 10 }), // encourage longer passwords
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { email, password } = req.body;
      const hashed = await bcrypt.hash(password, 12);

      // parameterized INSERT prevents SQL injection
      const result = await pool.query(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
        [email, hashed]
      );

      const userId = result.rows[0].id;
      res.status(201).json({ id: userId });
    } catch (err) {
      console.error(err);
      // avoid leaking DB errors (send generic message)
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// Login - verify password, issue access + refresh tokens
app.post(
  '/api/auth/login',
  csrfProtection,
  [body('email').isEmail().normalizeEmail(), body('password').exists()],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { email, password } = req.body;
      const userRes = await pool.query('SELECT id, password_hash FROM users WHERE email = $1', [
        email,
      ]);
      if (userRes.rowCount === 0) return res.status(401).json({ error: 'Invalid credentials' });

      const user = userRes.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return res.status(401).json({ error: 'Invalid credentials' });

      const accessToken = signAccessToken(user.id);
      const refreshToken = signRefreshToken(user.id);

      // Store refresh tokens server-side (DB) to allow rotation & revoke (example)
      await pool.query('INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)', [
        user.id,
        refreshToken,
      ]);

      // Send access token in body and refresh token as secure httpOnly cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({ accessToken });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// Refresh endpoint - rotate refresh tokens
app.post('/api/auth/refresh', csrfProtection, async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: 'No refresh token' });

    // verify token
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // check DB for existence
    const dbRes = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1', [token]);
    if (dbRes.rowCount === 0) return res.status(401).json({ error: 'Revoked refresh token' });

    const userId = payload.sub;
    // rotate: delete old, create new refresh token
    await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
    const newRefresh = signRefreshToken(userId);
    await pool.query('INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)', [
      userId,
      newRefresh,
    ]);

    res.cookie('refreshToken', newRefresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const accessToken = signAccessToken(userId);
    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not refresh token' });
  }
});

// Auth middleware for protected routes (uses Authorization header "Bearer <token>")
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing authorization header' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.userId = payload.sub;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Example protected route
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT id, email, created_at FROM users WHERE id = $1', [
      req.userId,
    ]);
    if (userRes.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: userRes.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Logout - revoke refresh token cookie and remove from DB
app.post('/api/auth/logout', csrfProtection, async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (token) {
      await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
      res.clearCookie('refreshToken');
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

// Error handling - do not leak stack traces in production
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Server error' : err.message });
});

// Start
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
