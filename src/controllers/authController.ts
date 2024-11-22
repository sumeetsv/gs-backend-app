import { Request, Response } from 'express';
import logger from '../logger/logger';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dbPromise from '../../database/database';
import { JwtPayload } from '../interfaces/JwtPayload';

// Register Controller
export const registerUser = async (req: Request, res: Response): Promise<void> => {
  const { username, password } = req.body;

  try {
    // Wait for the database to open
    const db = await dbPromise;

    // Check if the user already exists
    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', [username]);

    if (existingUser) {
      logger.warn(`Registration failed: User already exists with username: ${username}`);
      res.status(400).json({ message: 'Username already taken' });
      return;
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

    logger.info(`User registered successfully: ${username}`);

    // Send success response
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error instanceof Error) {
      logger.error(`Error during registration: ${error.message}`);
    } else {
      logger.error(`Error during registration: Unknown Error`);
    }
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Login Controller
export const login = async (req: Request, res: Response): Promise<void> => {
  const { username, password } = req.body;

  // Fetch user from DB
  const db = await dbPromise;
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);

  if (!user) {
    logger.warn(`Login failed for username: ${username}`);
    res.status(400).json({ message: 'Invalid credentials' });
    return;
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    logger.warn(`Invalid password attempt for username: ${username}`);
     res.status(400).json({ message: 'Invalid credentials' });
     return;
  }

  // Generate Access and Refresh Tokens
  const accessToken = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET!, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',  // Short-lived (Access Token)
  });

  const refreshToken = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',  // Long-lived (Refresh Token)
  });

  // Store Access and Refresh Tokens in HTTP-only, Secure Cookies
  res.cookie('accessToken', accessToken, {
    httpOnly: true,   // Only accessible by HTTP requests (not JavaScript)
    secure: process.env.NODE_ENV === 'production', // Set to true in production (HTTPS)
    maxAge: 15 * 60 * 1000, // 15 minutes (Access Token's expiration time)
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,   // Only accessible by HTTP requests (not JavaScript)
    secure: process.env.NODE_ENV === 'production', // Set to true in production (HTTPS)
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days (Refresh Token's expiration time)
  });

  // Return success message
  logger.info(`User logged in: ${username}`);
  res.json({ message: 'Login successful' });
};

// Logout Controller
export const logout = async (_req: Request, res: Response): Promise<void> => {
  // Clear both the access token and refresh token cookies
  res.clearCookie('accessToken', {
    httpOnly: true, // Ensures it can't be accessed by JavaScript
    secure: process.env.NODE_ENV === 'production', // Secure cookie in production
    sameSite: 'strict', // Helps with CSRF protection
  });

  res.clearCookie('refreshToken', {
    httpOnly: true, // Ensures it can't be accessed by JavaScript
    secure: process.env.NODE_ENV === 'production', // Secure cookie in production
    sameSite: 'strict', // Helps with CSRF protection
  });

  logger.info('User logged out');
  res.status(200).json({ message: 'Logged out successfully' });
};

// Refresh Token Controller
export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    logger.warn('Refresh token is missing');
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    // Verify the refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!) as JwtPayload;

    // Issue a new access token
    const newAccessToken = jwt.sign(
      { id: decoded.id, username: decoded.username },
      process.env.JWT_SECRET!,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
    );

    // Set the new access token in the response
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 15 * 60 * 1000, // 15 minutes (Access Token's expiration time)
    });

    res.json({ message: 'Access token refreshed' });
  } catch (error) {
    logger.error('Refresh token is invalid or expired');
    res.status(403).json({ message: 'Forbidden' });
  }
};