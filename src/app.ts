import express from 'express';
import authRoutes from './routes/authRoutes';
import dotenv from 'dotenv';
import { errorHandler } from './middleware/errorHandler';
import { initializeDB } from '../database/database';
import logger from './logger/logger';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();

// Middleware to parse JSON request bodies
app.use(express.json());

// Middleware to parse URL-encoded request bodies
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());  // Parse cookies for JWT

// Initialize the database
initializeDB()
  .then(() => logger.info('Database initialized successfully'))
  .catch((err) => logger.error(`Database initialization failed: ${err.message}`));

// Mount routes
app.use('/api/auth', authRoutes);

// Global error handler
app.use(errorHandler); 

export { app };
