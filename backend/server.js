require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./db');

const app = express();
app.use(cors({
  origin: 'http://localhost:5173', // Your frontend URL
  credentials: true // Allow cookies
}));
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET ;
const REFRESH_SECRET = process.env.REFRESH_SECRET ;

// Helper: Generate tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    { id: user.id },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  return { accessToken, refreshToken };
};

// Register
app.post('/register', async (req, res) => {
  try {
    const { username, password, role = 'user' } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await db.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *',
      [username, hashedPassword, role]
    );

    res.status(201).json({ id: user.rows[0].id });
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ error: 'Username exists' });
    } else {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValid = await bcrypt.compare(password, user.rows[0].password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0]);

    // Store refresh token in DB
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)',
      [user.rows[0].id, refreshToken]
    );

    // Set HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production' // HTTPS only in prod
    });

    res.json({ accessToken });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Refresh token
app.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token' });
    }

    // Verify token
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);

    // Check if token exists in DB
    const storedToken = await db.query(
      'SELECT * FROM refresh_tokens WHERE user_id = $1 AND token = $2',
      [decoded.id, refreshToken]
    );
    if (storedToken.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Get user data
    const user = await db.query('SELECT * FROM users WHERE id = $1', [decoded.id]);

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user.rows[0]);

    // Update refresh token in DB
    await db.query(
      'UPDATE refresh_tokens SET token = $1 WHERE token = $2',
      [newRefreshToken, refreshToken]
    );

    // Set new HTTP-only cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production'
    });

    res.json({ accessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/logout', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(400).json({ error: 'No refresh token' });
    }

    // Delete refresh token from DB
    await db.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);

    // Clear cookie
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out' });
  } catch (err) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Protected route (role-based)
app.get('/protected', async (req, res) => {
  try {
    const accessToken = req.headers.authorization?.split(' ')[1];
    if (!accessToken) {
      return res.status(401).json({ error: 'No access token' });
    }

    const decoded = jwt.verify(accessToken, JWT_SECRET);

    // Role check (example: admin-only)
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    res.json({ message: `Welcome admin ${decoded.id}` });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));