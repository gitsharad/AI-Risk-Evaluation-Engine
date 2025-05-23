import { CacheService } from '../../src/services/redisService';
import { jest, describe, beforeEach, afterEach, it, expect } from '@jest/globals';
import Redis from 'ioredis';

// Mock ioredis
jest.mock('ioredis');

describe('Cache Service', () => {
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Setup mock Redis instance
    mockRedis = {
      get: jest.fn(),
      set: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
      on: jest.fn(),
    } as unknown as jest.Mocked<Redis>;
    
    // Mock Redis constructor
    (Redis as unknown as jest.Mock).mockImplementation(() => mockRedis);
  });

  afterEach(() => {
    jest.resetModules();
  });

  describe('get', () => {
    it('should return parsed data from cache', async () => {
      const testData = { test: 'data' };
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(testData));

      const result = await CacheService.get('test-key');
      
      expect(result).toEqual(testData);
      expect(mockRedis.get).toHaveBeenCalledWith('test-key');
    });

    it('should return null when key not found', async () => {
      mockRedis.get.mockResolvedValueOnce(null);

      const result = await CacheService.get('non-existent-key');
      
      expect(result).toBeNull();
      expect(mockRedis.get).toHaveBeenCalledWith('non-existent-key');
    });

    it('should handle JSON parse errors', async () => {
      mockRedis.get.mockResolvedValueOnce('invalid-json');

      const result = await CacheService.get('invalid-key');
      
      expect(result).toBeNull();
    });
  });

  describe('set', () => {
    it('should set data with default TTL', async () => {
      const testData = { test: 'data' };
      
      await CacheService.set('test-key', testData);
      
      expect(mockRedis.set).toHaveBeenCalledWith(
        'test-key',
        JSON.stringify(testData),
        'EX',
        3600
      );
    });

    it('should set data with custom TTL', async () => {
      const testData = { test: 'data' };
      const customTTL = 1800;
      
      await CacheService.set('test-key', testData, customTTL);
      
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'test-key',
        customTTL,
        JSON.stringify(testData)
      );
    });
  });

  describe('del', () => {
    it('should delete key from cache', async () => {
      await CacheService.del('test-key');
      
      expect(mockRedis.del).toHaveBeenCalledWith('test-key');
    });
  });

  describe('generateRiskAnalysisKey', () => {
    it('should generate consistent cache key', () => {
      const data = {
        email: 'test@example.com',
        amount: 1000,
        ip: '192.168.1.1',
        deviceFingerprint: 'device123'
      };

      const key = CacheService.generateRiskAnalysisKey(data);
      
      expect(key).toBe('risk:test@example.com:1000:192.168.1.1:device123');
    });
  });
}); 