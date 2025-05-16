import axios from 'axios';
import { logger } from '../utils/logger';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Define the interface for LLM response
export interface LlmAnalysisResult {
  riskAssessment: string;
  riskScore: number;
  explanation: string[];
  additionalFlags: string[];
}

// Define the interface for LLM request data
export interface LlmRequestData {
  email: string;
  amount: number;
  ip: string;
  deviceFingerprint: string;
  currentRiskScore: number;
  currentRiskLevel: string;
  currentExplanations: string[];
}

/**
 * Get risk analysis from LLM
 */
export const getLlmRiskAnalysis = async (data: LlmRequestData): Promise<LlmAnalysisResult> => {
  try {
    const apiKey = process.env.OPENAI_API_KEY;
    
    if (!apiKey) {
      logger.error('OpenAI API key not found in environment variables');
      throw new Error('OpenAI API key not configured');
    }

    // Construct prompt for the LLM
    const prompt = constructRiskAnalysisPrompt(data);
    
    // Call OpenAI API
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4', // or gpt-3.5-turbo for lower cost
        messages: [
          {
            role: 'system', 
            content: 'You are a fraud detection AI assistant. Analyze transaction data and determine risk levels. Format your response as JSON.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.3, // Lower temperature for more focused and deterministic outputs
        response_format: { type: 'json_object' }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        }
      }
    );

    // Parse the response
    const responseContent = response.data.choices[0].message.content;
    const parsedResponse = JSON.parse(responseContent);
    
    // Validate and format the response
    return {
      riskAssessment: parsedResponse.riskAssessment || 'medium',
      riskScore: parsedResponse.riskScore || data.currentRiskScore,
      explanation: parsedResponse.explanation || data.currentExplanations,
      additionalFlags: parsedResponse.additionalFlags || []
    };
  } catch (error) {
    logger.error('Error getting LLM risk analysis:', error);
    
    // Return fallback response to ensure the main system still works
    return {
      riskAssessment: 'medium',
      riskScore: data.currentRiskScore,
      explanation: data.currentExplanations,
      additionalFlags: ['LLM analysis failed']
    };
  }
};

/**
 * Construct prompt for risk analysis
 */
const constructRiskAnalysisPrompt = (data: LlmRequestData): string => {
  return `
Analyze this payment transaction for potential fraud:

Transaction Details:
- Email: ${data.email}
- Amount: ${data.amount}
- IP Address: ${data.ip}
- Device Fingerprint: ${data.deviceFingerprint}

Current Risk Assessment:
- Risk Score: ${data.currentRiskScore} out of 100
- Risk Level: ${data.currentRiskLevel}
- Current Flags: ${data.currentExplanations.join('; ')}

Please provide a comprehensive fraud risk analysis including:
1. An overall risk assessment (low, medium, high)
2. A numerical risk score between 0-100
3. A list of explanations for your assessment
4. Any additional red flags not covered by the current system

Response must be valid JSON in this format:
{
  "riskAssessment": "low|medium|high",
  "riskScore": number,
  "explanation": ["reason1", "reason2", ...],
  "additionalFlags": ["flag1", "flag2", ...]
}
`;
}; 