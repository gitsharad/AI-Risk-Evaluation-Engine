import { evaluateRisk, TransactionData } from '../../src/services/riskService';
import RiskConfig, { getDefaultConfig, IRiskConfig } from '../../src/models/RiskConfig';
import FraudLog from '../../src/models/FraudLog';
import { jest, describe, beforeEach, it, expect } from '@jest/globals';

// Define mock types
type MockedGetDefaultConfig = jest.MockedFunction<typeof getDefaultConfig>;
type MockedFraudLogCreate = jest.MockedFunction<typeof FraudLog.create>;

// Mock the models
jest.mock('../../src/models/RiskConfig', () => ({
  __esModule: true,
  default: {
    findOne: jest.fn(),
    countDocuments: jest.fn(),
    create: jest.fn(),
  },
  getDefaultConfig: jest.fn(),
}));

jest.mock('../../src/models/FraudLog', () => ({
  __esModule: true,
  default: {
    create: jest.fn(),
  },
}));

// Reset the mocks before each test
beforeEach(() => {
  jest.resetAllMocks();
});

describe('Risk Service', () => {
  describe('evaluateRisk', () => {
    
    // Mock configuration for tests
    const mockConfig = {
      flaggedDomains: ['fraud.com', 'temp-mail.org'],
      thresholds: {
        low: 30,
        medium: 60,
        high: 80,
        amountThreshold: 10000,
      },
      suspiciousIps: ['192.168.1.100'],
      suspiciousDevices: ['device123'],
      save: jest.fn<() => Promise<IRiskConfig>>().mockResolvedValue(true as any),
    } as unknown as IRiskConfig;
    
    beforeEach(() => {
      // Setup the mock for getDefaultConfig
      (getDefaultConfig as MockedGetDefaultConfig).mockResolvedValue(mockConfig);
      (FraudLog.create as MockedFraudLogCreate).mockResolvedValue({} as any);
    });
    
    it('should return low risk for normal transaction', async () => {
      const transaction: TransactionData = {
        email: 'user@example.com',
        amount: 1000,
        ip: '192.168.1.1',
        deviceFingerprint: 'normaldevice',
      };
      
      const result = await evaluateRisk(transaction);
      
      expect(result.riskLevel).toBe('low');
      expect(result.score).toBeLessThan(0.3); // Updated for 0.0-1.0 scale
      expect(FraudLog.create).not.toHaveBeenCalled();
    });
    
    it('should flag high risk for suspicious email domain', async () => {
      const transaction: TransactionData = {
        email: 'user@fraud.com',
        amount: 1000,
        ip: '192.168.1.1',
        deviceFingerprint: 'normaldevice',
      };
      
      const result = await evaluateRisk(transaction);
      
      expect(result.riskLevel).not.toBe('low');
      expect(result.score).toBeGreaterThanOrEqual(0.5); // Updated for 0.0-1.0 scale
      expect(FraudLog.create).toHaveBeenCalled();
      expect(result.explanation.some(msg => msg.includes('fraud.com'))).toBe(true);
    });
    
    it('should increase risk for high amount', async () => {
      const transaction: TransactionData = {
        email: 'user@example.com',
        amount: 15000,
        ip: '192.168.1.1',
        deviceFingerprint: 'normaldevice',
      };
      
      const result = await evaluateRisk(transaction);
      
      expect(result.score).toBeGreaterThan(0);
      expect(result.explanation.some(msg => msg.includes('amount'))).toBe(true);
    });
    
    it('should flag high risk for suspicious IP', async () => {
      const transaction: TransactionData = {
        email: 'user@example.com',
        amount: 1000,
        ip: '192.168.1.100', // Suspicious IP from config
        deviceFingerprint: 'normaldevice',
      };
      
      const result = await evaluateRisk(transaction);
      
      expect(result.riskLevel).not.toBe('low');
      expect(result.score).toBeGreaterThanOrEqual(0.4); // Updated for 0.0-1.0 scale
      expect(FraudLog.create).toHaveBeenCalled();
      expect(result.explanation.some(msg => msg.includes('192.168.1.100'))).toBe(true);
    });
    
    it('should flag high risk for suspicious device', async () => {
      const transaction: TransactionData = {
        email: 'user@example.com',
        amount: 1000,
        ip: '192.168.1.1',
        deviceFingerprint: 'device123', // Suspicious device from config
      };
      
      const result = await evaluateRisk(transaction);
      
      expect(result.riskLevel).not.toBe('low');
      expect(result.score).toBeGreaterThanOrEqual(0.4); // Updated for 0.0-1.0 scale
      expect(FraudLog.create).toHaveBeenCalled();
      expect(result.explanation.some(msg => msg.includes('device123'))).toBe(true);
    });
    
    it('should handle multiple risk factors cumulatively', async () => {
      const transaction: TransactionData = {
        email: 'user@fraud.com',
        amount: 15000,
        ip: '192.168.1.100',
        deviceFingerprint: 'device123',
      };
      
      const result = await evaluateRisk(transaction);
      
      expect(result.riskLevel).toBe('high');
      expect(result.score).toBe(1.0); // Updated to 1.0 (max score)
      expect(FraudLog.create).toHaveBeenCalled();
      expect(result.explanation.length).toBeGreaterThanOrEqual(3);
    });
    
    it('should handle errors gracefully', async () => {
      (getDefaultConfig as MockedGetDefaultConfig).mockRejectedValue(new Error('Database error'));
      
      const transaction: TransactionData = {
        email: 'user@example.com',
        amount: 1000,
        ip: '192.168.1.1',
        deviceFingerprint: 'normaldevice',
      };
      
      await expect(evaluateRisk(transaction)).rejects.toThrow('Failed to evaluate risk');
    });
  });
}); 