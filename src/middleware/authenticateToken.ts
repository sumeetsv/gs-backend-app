import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import logger from '../logger/logger';

// Define User interface to match the structure of the JWT payload
interface User {
  id: number;
  username: string;
}

const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.accessToken;

  if (!token) {
    logger.warn('Access denied: No token provided');
    return res.status(401).json({ message: 'Access denied' });
  }

  try {
    // Verify the token and assert to the User type
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as User;

    // Attach user info to the request object
    (req as any).user = decoded;
    next();
  } catch (err) {
    logger.error('Invalid token');
    res.status(403).json({ message: 'Invalid token' });
  }
};

export default authenticateToken;
