require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./db');

const app = express();
app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

if (!JWT_SECRET || !REFRESH_SECRET) {
  throw new Error('JWT_SECRET and REFRESH_SECRET must be configured in backend/.env');
}

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

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    if (typeof username !== 'string' || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Use a valid username and a password of at least 8 characters' });
    }

    // Public registration must never allow a caller to assign themselves an admin role.
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await db.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, 'user') RETURNING id",
      [username.trim(), hashedPassword]
    );

    res.status(201).json({ id: user.rows[0].id });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error('Registration failed:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await db.query('SELECT * FROM users WHERE username = $1', [username.trim()]);
    if (user.rows.length === 0 || !(await bcrypt.compare(password, user.rows[0].password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0]);
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)',
      [user.rows[0].id, refreshToken]
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });
    res.json({ accessToken });
  } catch (err) {
    console.error('Login failed:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token' });
    }

    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const storedToken = await db.query(
      'SELECT * FROM refresh_tokens WHERE user_id = $1 AND token = $2',
      [decoded.id, refreshToken]
    );
    if (storedToken.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (userResult.rows.length === 0) {
      await db.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
      res.clearCookie('refreshToken', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', path: '/' });
      return res.status(401).json({ error: 'Account no longer exists' });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(userResult.rows[0]);
    await db.query(
      'UPDATE refresh_tokens SET token = $1 WHERE token = $2',
      [newRefreshToken, refreshToken]
    );

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });
    res.json({ accessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

app.post('/logout', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      await db.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    }
    res.clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });
    res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout failed:', err.message);
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.get('/protected', async (req, res) => {
  try {
    const accessToken = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : null;
    if (!accessToken) {
      return res.status(401).json({ error: 'No access token' });
    }

    const decoded = jwt.verify(accessToken, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    res.json({ message: `Welcome admin ${decoded.id}` });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

const PORT = Number(process.env.PORT) || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));