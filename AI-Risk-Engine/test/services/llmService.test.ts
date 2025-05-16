import { getLlmRiskAnalysis, LlmRequestData, LlmAnalysisResult } from '../../src/services/llmService';
import { jest, describe, beforeEach, afterEach, it, expect } from '@jest/globals';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock environment variables
const originalEnv = process.env;
beforeEach(() => {
  jest.resetAllMocks();
  process.env = { ...originalEnv, OPENAI_API_KEY: 'test-api-key' };
  
  // Spy on console methods
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  process.env = originalEnv;
});

describe('LLM Service', () => {
  const mockRequestData: LlmRequestData = {
    email: 'test@example.com',
    amount: 5000,
    ip: '192.168.1.1',
    deviceFingerprint: 'device123',
    currentRiskScore: 0.6,
    currentRiskLevel: 'moderate',
    currentExplanations: ['High transaction amount', 'Repeated IP usage']
  };
  
  const mockOpenAIResponse = {
    data: {
      choices: [
        {
          message: {
            content: JSON.stringify({
              riskAssessment: 'high',
              riskScore: 0.85,
              explanation: ['Suspicious email pattern', 'Transaction amount exceeds typical range'],
              additionalFlags: ['Unusual time of day', 'IP address associated with VPN'],
              summary: 'This transaction is considered high risk with a score of 0.85 due to: Suspicious email pattern; Transaction amount exceeds typical range'
            })
          }
        }
      ]
    }
  };

  it('should successfully get risk analysis from OpenAI', async () => {
    mockedAxios.post.mockResolvedValueOnce(mockOpenAIResponse);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(mockedAxios.post).toHaveBeenCalledWith(
      'https://api.openai.com/v1/chat/completions',
      expect.objectContaining({
        model: 'gpt-3.5-turbo',
        messages: expect.arrayContaining([
          expect.objectContaining({ role: 'system' }),
          expect.objectContaining({ role: 'user' })
        ])
      }),
      expect.objectContaining({
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-api-key'
        }
      })
    );
    
    expect(result).toEqual({
      riskAssessment: 'high',
      riskScore: 0.85,
      explanation: ['Suspicious email pattern', 'Transaction amount exceeds typical range'],
      additionalFlags: ['Unusual time of day', 'IP address associated with VPN'],
      summary: 'This transaction is considered high risk with a score of 0.85 due to: Suspicious email pattern; Transaction amount exceeds typical range'
    });
  });
  
  it('should normalize scores greater than 1.0 to a 0.0-1.0 scale', async () => {
    const largeScoreResponse = {
      data: {
        choices: [
          {
            message: {
              content: JSON.stringify({
                riskAssessment: 'high',
                riskScore: 92,
                explanation: ['Very high risk score'],
                additionalFlags: ['Score normalization test']
              })
            }
          }
        ]
      }
    };
    
    mockedAxios.post.mockResolvedValueOnce(largeScoreResponse);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(result.riskScore).toBeLessThanOrEqual(1.0);
    expect(result.riskScore).toBeCloseTo(0.92);
  });
  
  it('should generate a summary if not provided by LLM', async () => {
    const responseWithoutSummary = {
      data: {
        choices: [
          {
            message: {
              content: JSON.stringify({
                riskAssessment: 'moderate',
                riskScore: 0.6,
                explanation: ['Moderate risk indicators present'],
                additionalFlags: ['Some suspicious patterns']
              })
            }
          }
        ]
      }
    };
    
    mockedAxios.post.mockResolvedValueOnce(responseWithoutSummary);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(result.summary).toBeDefined();
    expect(result.summary).toContain('moderate risk');
    expect(result.summary).toContain('0.6');
  });
  
  it('should return fallback response when API key is missing', async () => {
    process.env.OPENAI_API_KEY = '';
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(mockedAxios.post).not.toHaveBeenCalled();
    expect(result).toEqual({
      riskAssessment: 'moderate',
      riskScore: mockRequestData.currentRiskScore,
      explanation: mockRequestData.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: expect.stringContaining(mockRequestData.currentRiskLevel)
    });
  });
  
  it('should handle network errors gracefully', async () => {
    const networkError = new Error('Network Error');
    mockedAxios.post.mockRejectedValueOnce(networkError);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(console.error).toHaveBeenCalled();
    expect(result).toEqual({
      riskAssessment: 'moderate',
      riskScore: mockRequestData.currentRiskScore,
      explanation: mockRequestData.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: expect.stringContaining(mockRequestData.currentRiskLevel)
    });
  });
  
  it('should handle API errors with response data gracefully', async () => {
    const mockError: any = new Error('API Error');
    mockError.response = {
      status: 429,
      statusText: 'Too Many Requests',
      data: { error: { message: 'Rate limit exceeded' } }
    };
    
    mockedAxios.post.mockRejectedValueOnce(mockError);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(console.error).toHaveBeenCalled();
    expect(result).toEqual({
      riskAssessment: 'moderate',
      riskScore: mockRequestData.currentRiskScore,
      explanation: mockRequestData.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: expect.stringContaining(mockRequestData.currentRiskLevel)
    });
  });
  
  it('should handle API errors without response data gracefully', async () => {
    const mockError: any = new Error('API Error');
    // No response property, to test that branch of the error handling
    
    mockedAxios.post.mockRejectedValueOnce(mockError);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(console.error).toHaveBeenCalled();
    expect(result).toEqual({
      riskAssessment: 'moderate',
      riskScore: mockRequestData.currentRiskScore,
      explanation: mockRequestData.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: expect.stringContaining(mockRequestData.currentRiskLevel)
    });
  });
  
  it('should handle malformed JSON responses', async () => {
    const malformedResponse = {
      data: {
        choices: [
          {
            message: {
              content: '{invalid-json}'
            }
          }
        ]
      }
    };
    
    mockedAxios.post.mockResolvedValueOnce(malformedResponse);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(console.error).toHaveBeenCalled();
    expect(result).toEqual({
      riskAssessment: 'moderate',
      riskScore: mockRequestData.currentRiskScore,
      explanation: mockRequestData.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: expect.stringContaining(mockRequestData.currentRiskLevel)
    });
  });
  
  it('should handle incomplete/missing response fields', async () => {
    const incompleteResponse = {
      data: {
        choices: [
          {
            message: {
              content: JSON.stringify({
                // Missing riskAssessment and riskScore
                explanation: [],
                additionalFlags: []
              })
            }
          }
        ]
      }
    };
    
    mockedAxios.post.mockResolvedValueOnce(incompleteResponse);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    // Should use fallback values for missing fields
    expect(result.riskAssessment).toBe('moderate');
    expect(result.riskScore).toBe(mockRequestData.currentRiskScore);
    expect(result.summary).toBeDefined();
  });
  
  it('should handle unexpected response structure', async () => {
    const unexpectedResponse = {
      data: {
        // Missing the choices array
        status: 'success'
      }
    };
    
    mockedAxios.post.mockResolvedValueOnce(unexpectedResponse as any);
    
    const result = await getLlmRiskAnalysis(mockRequestData);
    
    expect(console.error).toHaveBeenCalled();
    expect(result).toEqual({
      riskAssessment: 'moderate',
      riskScore: mockRequestData.currentRiskScore,
      explanation: mockRequestData.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: expect.stringContaining(mockRequestData.currentRiskLevel)
    });
  });
}); 