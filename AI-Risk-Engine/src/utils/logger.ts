import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Create logs directory if it doesn't exist
const logDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logFilePath = process.env.LOG_FILE_PATH || path.join(logDir, 'fraud.log');
const logToFile = process.env.LOG_TO_FILE === 'true';

// Define logger configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'ai-risk-engine' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(
          ({ timestamp, level, message, ...rest }) =>
            `${timestamp} ${level}: ${message} ${
              Object.keys(rest).length > 0 ? JSON.stringify(rest) : ''
            }`
        )
      ),
    }),
  ],
});

// Add file transport if LOG_TO_FILE is true
if (logToFile) {
  logger.add(
    new winston.transports.File({
      filename: logFilePath,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    })
  );
  
  // Add specific fraud log transport
  logger.add(
    new winston.transports.File({
      filename: path.join(logDir, 'fraud.log'),
      level: 'warn',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    })
  );
}

export { logger }; 