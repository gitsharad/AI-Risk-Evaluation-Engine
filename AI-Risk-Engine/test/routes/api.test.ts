import request from 'supertest';
import express from 'express';
import apiRoutes from '../../src/routes/api';
import { evaluateRisk, getFraudStats, RiskEvaluationResult } from '../../src/services/riskService';
import { jest, describe, beforeEach, it, expect } from '@jest/globals';

// Create proper types for mocked functions
type MockedEvaluateRisk = jest.MockedFunction<typeof evaluateRisk>;
type MockedGetFraudStats = jest.MockedFunction<typeof getFraudStats>;

// Mock the risk service
jest.mock('../../src/services/riskService', () => ({
  __esModule: true,
  evaluateRisk: jest.fn(),
  getFraudStats: jest.fn(),
}));

// Create express app for testing
const app = express();
app.use(express.json());
app.use('/api', apiRoutes);

// Add generic error handler for tests
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  res.status(500).json({ error: err.message });
});

describe('API Routes', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });
  
  describe('POST /api/evaluate-risk', () => {
    it('should evaluate risk for valid transaction data', async () => {
      const mockResult: RiskEvaluationResult = {
        score: 0.25,
        riskLevel: 'low',
        explanation: ['No suspicious activity detected'],
      };
      
      (evaluateRisk as MockedEvaluateRisk).mockResolvedValue(mockResult);
      
      const response = await request(app)
        .post('/api/evaluate-risk')
        .send({
          email: 'user@example.com',
          amount: 1000,
          ip: '192.168.1.1',
          deviceFingerprint: 'device123',
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual(mockResult);
      expect(evaluateRisk).toHaveBeenCalledWith({
        email: 'user@example.com',
        amount: 1000,
        ip: '192.168.1.1',
        deviceFingerprint: 'device123',
        enableLlmAnalysis: false
      });
    });
    
    it('should return 400 for missing required fields', async () => {
      const response = await request(app)
        .post('/api/evaluate-risk')
        .send({
          email: 'user@example.com',
          // amount is missing
          ip: '192.168.1.1',
          deviceFingerprint: 'device123',
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(evaluateRisk).not.toHaveBeenCalled();
    });
    
    it('should return 400 for invalid email format', async () => {
      const response = await request(app)
        .post('/api/evaluate-risk')
        .send({
          email: 'invalid-email',
          amount: 1000,
          ip: '192.168.1.1',
          deviceFingerprint: 'device123',
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(evaluateRisk).not.toHaveBeenCalled();
    });
    
    it('should return 400 for invalid amount', async () => {
      const response = await request(app)
        .post('/api/evaluate-risk')
        .send({
          email: 'user@example.com',
          amount: -100, // Negative amount
          ip: '192.168.1.1',
          deviceFingerprint: 'device123',
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(evaluateRisk).not.toHaveBeenCalled();
    });
    
    it('should handle errors from risk service', async () => {
      (evaluateRisk as MockedEvaluateRisk).mockRejectedValue(new Error('Service error'));
      
      const response = await request(app)
        .post('/api/evaluate-risk')
        .send({
          email: 'user@example.com',
          amount: 1000,
          ip: '192.168.1.1',
          deviceFingerprint: 'device123',
        });
      
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Service error');
    });
  });
  
  describe('GET /api/fraud-stats', () => {
    it('should return fraud statistics', async () => {
      const mockStats = {
        totalAttempts: 100,
        byRiskLevel: {
          low: { count: 50, averageScore: 0.2 },
          moderate: { count: 30, averageScore: 0.5 },
          high: { count: 20, averageScore: 0.85 },
        },
      };
      
      (getFraudStats as MockedGetFraudStats).mockResolvedValue(mockStats);
      
      const response = await request(app).get('/api/fraud-stats');
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual(mockStats);
      expect(getFraudStats).toHaveBeenCalled();
    });
    
    it('should handle errors from fraud stats service', async () => {
      (getFraudStats as MockedGetFraudStats).mockRejectedValue(new Error('Stats error'));
      
      const response = await request(app).get('/api/fraud-stats');
      
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Stats error');
    });
  });
}); 