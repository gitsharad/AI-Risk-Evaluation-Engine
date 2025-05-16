import { logger } from '../utils/logger';
import { getDefaultConfig } from '../models/RiskConfig';
import FraudLog, { IFraudLog } from '../models/FraudLog';
import { getLlmRiskAnalysis, LlmRequestData } from './llmService';

// Define the transaction data structure
export interface TransactionData {
  email: string;
  amount: number;
  ip: string;
  deviceFingerprint: string;
  enableLlmAnalysis?: boolean;
}

// Define the risk evaluation result
export interface RiskEvaluationResult {
  score: number;
  riskLevel: 'low' | 'medium' | 'high';
  explanation: string[];
  llmEnhanced?: boolean;
  llmFlags?: string[];
}

// Stats interface
export interface FraudStats {
  totalAttempts: number;
  byRiskLevel: {
    low: { count: number; averageScore: number };
    medium: { count: number; averageScore: number };
    high: { count: number; averageScore: number };
  };
}

// Data needed to create a fraud log
interface FraudLogData {
  email: string;
  amount: number;
  ip: string;
  deviceFingerprint: string;
  score: number;
  riskLevel: 'low' | 'medium' | 'high';
  reason: string;
  llmEnhanced?: boolean;
  llmFlags?: string[];
}

// Cache for recent IPs and device fingerprints
interface Cache {
  ips: Map<string, number>;
  devices: Map<string, number>;
}

// Simple in-memory cache for IPs and device fingerprints
const recentActivityCache: Cache = {
  ips: new Map<string, number>(),
  devices: new Map<string, number>(),
};

/**
 * Evaluate the risk of a transaction
 */
export const evaluateRisk = async (
  transaction: TransactionData
): Promise<RiskEvaluationResult> => {
  try {
    // Load config
    const config = await getDefaultConfig();
    
    let score = 0;
    const reasons: string[] = [];

    // 1. Check email domain against flagged domains
    const emailDomain = transaction.email.split('@')[1]?.toLowerCase();
    if (emailDomain && config.flaggedDomains.includes(emailDomain)) {
      score += 50;
      reasons.push(`Email domain '${emailDomain}' is in the flagged list`);
    }

    // 2. Check transaction amount against threshold
    if (transaction.amount > config.thresholds.amountThreshold) {
      const amountFactor = Math.min(
        30,
        (transaction.amount / config.thresholds.amountThreshold) * 10
      );
      score += amountFactor;
      reasons.push(`Transaction amount ₹${transaction.amount} exceeds threshold of ₹${config.thresholds.amountThreshold}`);
    }

    // 3. Check IP address against suspicious IPs
    if (config.suspiciousIps.includes(transaction.ip)) {
      score += 40;
      reasons.push(`IP address ${transaction.ip} is in the suspicious list`);
    }

    // 4. Check device fingerprint against suspicious devices
    if (config.suspiciousDevices.includes(transaction.deviceFingerprint)) {
      score += 40;
      reasons.push(`Device fingerprint ${transaction.deviceFingerprint} is in the suspicious list`);
    }

    // 5. Check for repeated IP activity
    const ipCount = recentActivityCache.ips.get(transaction.ip) || 0;
    if (ipCount > 0) {
      const ipFactor = Math.min(20, ipCount * 5);
      score += ipFactor;
      reasons.push(`IP address ${transaction.ip} has been used ${ipCount} times recently`);
    }
    recentActivityCache.ips.set(transaction.ip, ipCount + 1);

    // 6. Check for repeated device activity
    const deviceCount = recentActivityCache.devices.get(transaction.deviceFingerprint) || 0;
    if (deviceCount > 0) {
      const deviceFactor = Math.min(20, deviceCount * 5);
      score += deviceFactor;
      reasons.push(`Device fingerprint ${transaction.deviceFingerprint} has been used ${deviceCount} times recently`);
    }
    recentActivityCache.devices.set(transaction.deviceFingerprint, deviceCount + 1);

    // Cap the score at 100
    score = Math.min(100, score);

    // Determine risk level based on thresholds
    let riskLevel: 'low' | 'medium' | 'high';
    if (score >= config.thresholds.high) {
      riskLevel = 'high';
    } else if (score >= config.thresholds.medium) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    let llmEnhanced = false;
    let llmFlags: string[] = [];

    // Use LLM for enhanced analysis if enabled
    if (transaction.enableLlmAnalysis && process.env.OPENAI_API_KEY) {
      try {
        // Prepare data for LLM analysis
        const llmData: LlmRequestData = {
          email: transaction.email,
          amount: transaction.amount,
          ip: transaction.ip,
          deviceFingerprint: transaction.deviceFingerprint,
          currentRiskScore: score,
          currentRiskLevel: riskLevel,
          currentExplanations: reasons,
        };

        // Get LLM analysis
        logger.info('Requesting LLM analysis for transaction', { email: transaction.email });
        const llmResult = await getLlmRiskAnalysis(llmData);
        
        // Incorporate LLM analysis into the risk assessment
        llmEnhanced = true;
        
        // Adjust score based on LLM input (weighted blend)
        const ruleBasedWeight = 0.7; // 70% weight to rule-based system
        const llmWeight = 0.3; // 30% weight to LLM
        score = Math.min(100, Math.round(
          (score * ruleBasedWeight) + (llmResult.riskScore * llmWeight)
        ));
        
        // Re-determine risk level based on new score
        if (score >= config.thresholds.high) {
          riskLevel = 'high';
        } else if (score >= config.thresholds.medium) {
          riskLevel = 'medium';
        } else {
          riskLevel = 'low';
        }
        
        // Add LLM-specific flags
        llmFlags = llmResult.additionalFlags;
        
        // Add LLM explanations to our reasons
        llmResult.explanation.forEach(explanation => {
          if (!reasons.includes(explanation)) {
            reasons.push(explanation);
          }
        });
        
        logger.info('LLM analysis completed', { 
          originalScore: llmData.currentRiskScore,
          llmScore: llmResult.riskScore,
          finalScore: score
        });
      } catch (error) {
        logger.error('Error during LLM analysis, continuing with rule-based assessment only:', error);
      }
    }

    // Log fraud attempts if risk is not low
    if (riskLevel !== 'low') {
      await logFraudAttempt({
        email: transaction.email,
        amount: transaction.amount,
        ip: transaction.ip,
        deviceFingerprint: transaction.deviceFingerprint,
        score,
        riskLevel,
        reason: reasons.join('; '),
        llmEnhanced,
        llmFlags
      });
    }

    // Periodically clean up the cache (every 100 evaluations)
    const totalCacheEntries = recentActivityCache.ips.size + recentActivityCache.devices.size;
    if (totalCacheEntries > 10000) {
      cleanupCache();
    }

    return {
      score,
      riskLevel,
      explanation: reasons,
      llmEnhanced,
      llmFlags
    };
  } catch (error) {
    logger.error('Error evaluating risk:', error);
    throw new Error('Failed to evaluate risk');
  }
};

/**
 * Log fraud attempts to MongoDB
 */
const logFraudAttempt = async (data: FraudLogData): Promise<void> => {
  try {
    await FraudLog.create(data);
    logger.warn('Fraud attempt logged', { ...data });
  } catch (error) {
    logger.error('Error logging fraud attempt:', error);
  }
};

/**
 * Clean up the activity cache
 */
const cleanupCache = (): void => {
  // Remove old entries to prevent memory leaks
  const newIpMap = new Map<string, number>();
  const newDeviceMap = new Map<string, number>();

  // Keep only the entries with higher counts
  // Sort by count and keep top 1000
  const sortedIps = [...recentActivityCache.ips.entries()].sort((a, b) => b[1] - a[1]).slice(0, 1000);
  const sortedDevices = [...recentActivityCache.devices.entries()].sort((a, b) => b[1] - a[1]).slice(0, 1000);

  sortedIps.forEach(([ip, count]) => newIpMap.set(ip, count));
  sortedDevices.forEach(([device, count]) => newDeviceMap.set(device, count));

  recentActivityCache.ips = newIpMap;
  recentActivityCache.devices = newDeviceMap;

  logger.info('Activity cache cleaned up', { 
    ipsRemaining: recentActivityCache.ips.size,
    devicesRemaining: recentActivityCache.devices.size,
  });
};

/**
 * Get fraud statistics
 */
export const getFraudStats = async (): Promise<FraudStats> => {
  try {
    // Get count by risk level
    const riskLevelCounts = await FraudLog.aggregate([
      {
        $group: {
          _id: '$riskLevel',
          count: { $sum: 1 },
          averageScore: { $avg: '$score' },
        },
      },
    ]);

    // Format the results
    const stats: FraudStats = {
      totalAttempts: 0,
      byRiskLevel: {
        low: { count: 0, averageScore: 0 },
        medium: { count: 0, averageScore: 0 },
        high: { count: 0, averageScore: 0 },
      },
    };

    riskLevelCounts.forEach((item: { _id: 'low' | 'medium' | 'high'; count: number; averageScore: number }) => {
      stats.byRiskLevel[item._id] = {
        count: item.count,
        averageScore: Math.round(item.averageScore * 100) / 100,
      };
      stats.totalAttempts += item.count;
    });

    return stats;
  } catch (error) {
    logger.error('Error getting fraud stats:', error);
    throw new Error('Failed to get fraud statistics');
  }
}; 