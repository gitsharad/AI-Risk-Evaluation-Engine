import express, { Request, Response, NextFunction, Router } from 'express';
import { evaluateRisk, getFraudStats, TransactionData } from '../services/riskService';
import { logger } from '../utils/logger';
import rateLimit from 'express-rate-limit';

const router: Router = express.Router();

// Apply rate limiting middleware for API routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: { error: 'Too many requests, please try again later.' },
});

// Apply rate limiter to all routes
router.use(apiLimiter);

/**
 * @route POST /api/evaluate-risk
 * @desc Evaluate risk for a transaction
 * @access Public
 */
router.post(
  '/evaluate-risk', 
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, amount, ip, deviceFingerprint }: TransactionData = req.body;

      // Validate required fields
      if (!email || !amount || !ip || !deviceFingerprint) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: email, amount, ip, deviceFingerprint',
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid email format',
        });
      }

      // Validate amount is a positive number
      if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({
          success: false,
          error: 'Amount must be a positive number',
        });
      }

      // Get client IP from request if not provided
      const clientIp = ip || req.ip || req.socket.remoteAddress || 'unknown';

      // Evaluate risk
      const result = await evaluateRisk({
        email,
        amount,
        ip: clientIp,
        deviceFingerprint,
      });

      // Return the risk evaluation result
      return res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('Error in risk evaluation endpoint:', error);
      next(error);
    }
  }
);

/**
 * @route GET /api/fraud-stats
 * @desc Get fraud statistics
 * @access Public
 */
router.get(
  '/fraud-stats', 
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const stats = await getFraudStats();

      return res.status(200).json({
        success: true,
        data: stats,
      });
    } catch (error) {
      logger.error('Error in fraud stats endpoint:', error);
      next(error);
    }
  }
);

export default router; 