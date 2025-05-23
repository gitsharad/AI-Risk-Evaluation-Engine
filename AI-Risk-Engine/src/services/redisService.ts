import Redis from 'ioredis';
import { logger } from '../utils/logger';
import dotenv from 'dotenv';

dotenv.config();

// Redis configuration
const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379');
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
const REDIS_TTL = parseInt(process.env.REDIS_TTL || '3600'); // Default TTL: 1 hour

// Create Redis client
const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  }
});

// Handle Redis connection events
redis.on('connect', () => {
  logger.info('Connected to Redis');
});

redis.on('error', (error) => {
  logger.error('Redis connection error:', error);
});

/**
 * Cache service for storing and retrieving data
 */
export class CacheService {
  /**
   * Get data from cache
   * @param key Cache key
   * @returns Cached data or null if not found
   */
  static async get<T>(key: string): Promise<T | null> {
    try {
      const data = await redis.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      logger.error('Error getting data from cache:', error);
      return null;
    }
  }

  /**
   * Set data in cache
   * @param key Cache key
   * @param value Data to cache
   * @param ttl Time to live in seconds (optional)
   */
  static async set(key: string, value: any, ttl?: number): Promise<void> {
    try {
      const stringValue = JSON.stringify(value);
      if (ttl) {
        await redis.setex(key, ttl, stringValue);
      } else {
        await redis.set(key, stringValue, 'EX', REDIS_TTL);
      }
    } catch (error) {
      logger.error('Error setting data in cache:', error);
    }
  }

  /**
   * Delete data from cache
   * @param key Cache key
   */
  static async del(key: string): Promise<void> {
    try {
      await redis.del(key);
    } catch (error) {
      logger.error('Error deleting data from cache:', error);
    }
  }

  /**
   * Generate cache key for risk analysis
   * @param data Transaction data
   * @returns Cache key
   */
  static generateRiskAnalysisKey(data: {
    email: string;
    amount: number;
    ip: string;
    deviceFingerprint: string;
  }): string {
    return `risk:${data.email}:${data.amount}:${data.ip}:${data.deviceFingerprint}`;
  }
}

export default CacheService; 