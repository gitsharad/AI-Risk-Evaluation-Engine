import request from 'supertest';
import express from 'express';
import apiRoutes from '../../src/routes/api';
import { evaluateRisk, getFraudStats } from '../../src/services/riskService';

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
      const mockResult = {
        score: 25,
        riskLevel: 'low',
        explanation: ['No suspicious activity detected'],
      };
      
      (evaluateRisk as jest.Mock).mockResolvedValue(mockResult);
      
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
      (evaluateRisk as jest.Mock).mockRejectedValue(new Error('Service error'));
      
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
          low: { count: 50, averageScore: 20 },
          medium: { count: 30, averageScore: 50 },
          high: { count: 20, averageScore: 85 },
        },
      };
      
      (getFraudStats as jest.Mock).mockResolvedValue(mockStats);
      
      const response = await request(app).get('/api/fraud-stats');
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual(mockStats);
      expect(getFraudStats).toHaveBeenCalled();
    });
    
    it('should handle errors from fraud stats service', async () => {
      (getFraudStats as jest.Mock).mockRejectedValue(new Error('Stats error'));
      
      const response = await request(app).get('/api/fraud-stats');
      
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Stats error');
    });
  });
}); 