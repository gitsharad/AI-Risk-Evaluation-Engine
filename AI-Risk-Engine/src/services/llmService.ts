import axios from 'axios';
import { logger } from '../utils/logger';
import dotenv from 'dotenv';
import CacheService from './redisService';

// Load environment variables
dotenv.config();

// Define the interface for LLM response
export interface LlmAnalysisResult {
  riskAssessment: string;
  riskScore: number; // 0.0-1.0 scale
  explanation: string[];
  additionalFlags: string[];
  summary: string; // Condensed explanation for the risk assessment
}

// Define the interface for LLM request data
export interface LlmRequestData {
  email: string;
  amount: number;
  ip: string;
  deviceFingerprint: string;
  currentRiskScore: number; // 0.0-1.0 scale
  currentRiskLevel: string;
  currentExplanations: string[];
}

/**
 * Get risk analysis from LLM
 */
export const getLlmRiskAnalysis = async (data: LlmRequestData): Promise<LlmAnalysisResult> => {
  try {
    // Check cache first
    const cacheKey = CacheService.generateRiskAnalysisKey(data);
    const cachedResult = await CacheService.get<LlmAnalysisResult>(cacheKey);
    
    if (cachedResult) {
      logger.info('Retrieved risk analysis from cache');
      return cachedResult;
    }

    // Debug: Log the environment variables
    console.log('DEBUG: Environment variables loaded:', {
      hasOpenAIKey: process.env.OPENAI_API_KEY ? 'Yes (length: ' + process.env.OPENAI_API_KEY.length + ')' : 'No',
      nodeEnv: process.env.NODE_ENV,
      port: process.env.PORT
    });
    
    const apiKey = process.env.OPENAI_API_KEY;
    
    if (!apiKey) {
      console.error('DEBUG: OpenAI API key not found in environment variables');
      logger.error('OpenAI API key not found in environment variables');
      throw new Error('OpenAI API key not configured');
    }

    // Debug: Log that we're about to create the prompt
    console.log('DEBUG: Creating prompt for OpenAI');
    
    // Construct prompt for the LLM
    const prompt = constructRiskAnalysisPrompt(data);
    
    // Debug: Log request details (without sensitive data)
    console.log('DEBUG: About to make OpenAI API request with model: gpt-3.5-turbo');
    
    try {
      // Call OpenAI API
      console.log('DEBUG: Sending request to OpenAI API...');
      const response = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        {
          model: 'gpt-3.5-turbo',
          messages: [
            {
              role: 'system', 
              content: 'You are a fraud detection AI assistant specializing in payment fraud analysis. Your task is to analyze transaction data, identify potential risks, and provide detailed explanations for your assessment.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.3,
          response_format: { type: 'json_object' }
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          }
        }
      );
      
      console.log('DEBUG: Response received from OpenAI API');
      
      // Parse the response
      const responseContent = response.data.choices[0].message.content;
      console.log('DEBUG: Raw response content:', responseContent);
      
      const parsedResponse = JSON.parse(responseContent);
      console.log('DEBUG: Parsed response:', parsedResponse);
      
      // Ensure score is in 0.0-1.0 range
      let normalizedScore = parsedResponse.riskScore;
      if (normalizedScore > 1) {
        normalizedScore = normalizedScore / 100;
      }
      
      // Generate a summary if not provided by the LLM
      const summary = parsedResponse.summary || generateSummary(
        parsedResponse.riskAssessment || data.currentRiskLevel,
        normalizedScore || data.currentRiskScore,
        parsedResponse.explanation || data.currentExplanations,
        data
      );
      
      // Create the result object
      const result: LlmAnalysisResult = {
        riskAssessment: parsedResponse.riskAssessment || 'moderate',
        riskScore: normalizedScore || data.currentRiskScore,
        explanation: parsedResponse.explanation || data.currentExplanations,
        additionalFlags: parsedResponse.additionalFlags || [],
        summary: summary
      };

      // Cache the result
      await CacheService.set(cacheKey, result);
      logger.info('Cached risk analysis result');

      return result;
    } catch (error: any) {
      console.error('DEBUG: Error during OpenAI API call:', error.message);
      if (error.response) {
        console.error('DEBUG: API error response:', {
          status: error.response.status,
          statusText: error.response.statusText,
          data: error.response.data
        });
      }
      throw error;
    }
  } catch (error) {
    console.error('DEBUG: Overall error in getLlmRiskAnalysis:', error);
    logger.error('Error getting LLM risk analysis:', error);
    
    // Return fallback response to ensure the main system still works
    return {
      riskAssessment: 'moderate',
      riskScore: data.currentRiskScore,
      explanation: data.currentExplanations,
      additionalFlags: ['LLM analysis failed'],
      summary: `Transaction risk level: ${data.currentRiskLevel} with score ${data.currentRiskScore}. ${data.currentExplanations[0] || 'No specific risk factors identified.'}`
    };
  }
};

/**
 * Generate a summary explanation based on the analysis results
 */
const generateSummary = (
  riskLevel: string, 
  score: number, 
  explanations: string[], 
  data: LlmRequestData
): string => {
  // Format score to 2 decimal places
  const formattedScore = Math.round(score * 100) / 100;
  
  // Get the top 1-3 most important explanations
  const topExplanations = explanations.slice(0, Math.min(3, explanations.length));
  
  // Construct reason string
  let reasonStr = topExplanations.length > 0 
    ? topExplanations.join('; ')
    : data.currentExplanations[0] || 'No specific risk factors identified';
    
  // Build the summary
  return `This transaction is considered ${riskLevel} risk with a score of ${formattedScore} due to: ${reasonStr}`;
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
- Risk Score: ${data.currentRiskScore} (scale: 0.0-1.0)
- Risk Level: ${data.currentRiskLevel}
- Current Risk Indicators: ${data.currentExplanations.join('; ')}

Your task is to:
1. Analyze the transaction data for potential fraud indicators
2. Consider patterns like unusual transaction amounts, suspicious email domains, and device/IP fingerprints
3. Look for behavioral anomalies not captured by the rule-based system
4. Assess the overall fraud risk

Respond with a detailed fraud risk analysis in this JSON format:
{
  "riskAssessment": "low|moderate|high",
  "riskScore": [number between 0.0-1.0],
  "explanation": [
    "Detailed explanation of risk factor 1",
    "Detailed explanation of risk factor 2",
    ...
  ],
  "additionalFlags": [
    "Additional suspicious pattern 1",
    "Additional suspicious pattern 2",
    ...
  ],
  "summary": "A single sentence summary of the risk assessment including the most important factors"
}

Provide specific, detailed explanations rather than general statements. Include behavioral insights and pattern recognition that go beyond simple rule-based flags.
`;
}; 