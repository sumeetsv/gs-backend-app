import winston from 'winston';

// Create a logger instance
const logger = winston.createLogger({
  level: 'info',  // Log level (can be 'debug', 'info', 'warn', 'error')
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console({ format: winston.format.simple() }),
    new winston.transports.File({ filename: 'logs/app.log' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }), // Log errors to a file
  ]
});

export default logger;
