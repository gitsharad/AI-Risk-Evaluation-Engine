import dotenv from 'dotenv';
import { logger } from '../utils/logger';
import path from 'path';
import fs from 'fs';
import RiskConfig, { IRiskConfig, getDefaultConfig } from '../models/RiskConfig';

// Load environment variables
dotenv.config();

// Base application configs
export const appConfig = {
  port: parseInt(process.env.PORT || '6000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',
  mongoUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/ai-risk-engine',
  logToFile: process.env.LOG_TO_FILE === 'true',
  logLevel: process.env.LOG_LEVEL || 'info',
  jwtSecret: process.env.JWT_SECRET || 'default_jwt_secret',
};

/**
 * Get risk configuration from database
 */
export const getRiskConfig = async (): Promise<IRiskConfig> => {
  try {
    return await getDefaultConfig();
  } catch (error) {
    logger.error('Error loading risk configuration:', error);
    throw new Error('Failed to load risk configuration');
  }
};

/**
 * Update risk configuration
 */
export const updateRiskConfig = async (updates: Partial<IRiskConfig>): Promise<IRiskConfig> => {
  try {
    const config = await getDefaultConfig();
    
    // Update the configuration with the provided changes
    Object.keys(updates).forEach((key) => {
      if (key in config && key !== '_id') {
        // @ts-ignore - we've checked that the key exists
        config[key] = updates[key];
      }
    });
    
    await config.save();
    logger.info('Risk configuration updated successfully');
    
    return config;
  } catch (error) {
    logger.error('Error updating risk configuration:', error);
    throw new Error('Failed to update risk configuration');
  }
};

/**
 * Load risk configuration from JSON file (for initial setup)
 */
export const loadConfigFromFile = async (filePath: string): Promise<IRiskConfig> => {
  try {
    const resolvedPath = path.resolve(process.cwd(), filePath);
    const fileContent = fs.readFileSync(resolvedPath, 'utf8');
    const configData = JSON.parse(fileContent);
    
    return await updateRiskConfig(configData);
  } catch (error) {
    logger.error(`Error loading configuration from file ${filePath}:`, error);
    throw new Error('Failed to load configuration from file');
  }
}; 