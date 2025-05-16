import mongoose, { Schema, Document } from 'mongoose';

export interface IRiskConfig extends Document {
  flaggedDomains: string[];
  thresholds: {
    low: number;
    medium: number;
    high: number;
    amountThreshold: number;
  };
  suspiciousIps: string[];
  suspiciousDevices: string[];
  updatedAt: Date;
}

const RiskConfigSchema: Schema = new Schema(
  {
    flaggedDomains: {
      type: [String],
      default: ['fraud.com', 'temp-mail.org', 'fakeemail.com'],
    },
    thresholds: {
      low: {
        type: Number,
        default: 30,
        min: 0,
        max: 100,
      },
      medium: {
        type: Number,
        default: 60,
        min: 0,
        max: 100,
      },
      high: {
        type: Number,
        default: 80,
        min: 0,
        max: 100,
      },
      amountThreshold: {
        type: Number,
        default: 10000, // ₹10,000
        min: 0,
      },
    },
    suspiciousIps: {
      type: [String],
      default: [],
    },
    suspiciousDevices: {
      type: [String],
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

// Create a singleton model
export const getDefaultConfig = async (): Promise<IRiskConfig> => {
  const RiskConfig = mongoose.model<IRiskConfig>('RiskConfig', RiskConfigSchema);
  const count = await RiskConfig.countDocuments();
  
  if (count === 0) {
    // Create default configuration if none exists
    return await RiskConfig.create({});
  }
  
  // Return the first (and only) configuration
  const config = await RiskConfig.findOne({});
  if (!config) {
    // If for some reason we can't find the config, create a new one
    return await RiskConfig.create({});
  }
  return config;
};

export default mongoose.model<IRiskConfig>('RiskConfig', RiskConfigSchema); 