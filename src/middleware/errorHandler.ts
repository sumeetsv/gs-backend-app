import { Request, Response, NextFunction } from 'express';
import logger from '../logger/logger';

export const errorHandler = (err: unknown, req: Request, res: Response, next: NextFunction): void => {

    if (err instanceof Error) {
        logger.error({
            message: err.message,
            stack: err.stack,
            route: req.originalUrl,
            method: req.method,
        });
    } else {
        logger.error({
            message: 'Unknown error occurred',
            route: req.originalUrl,
            method: req.method,
        });
    }

    res.status(500).json({
        message: 'An unexpected error occurred. Please try again later.',
    });
};
