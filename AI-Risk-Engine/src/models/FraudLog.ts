import mongoose, { Schema, Document } from 'mongoose';

export interface IFraudLog extends Document {
  email: string;
  amount: number;
  ip: string;
  deviceFingerprint: string;
  score: number;
  riskLevel: 'low' | 'moderate' | 'high';
  reason: string;
  createdAt: Date;
  llmEnhanced?: boolean;
  llmFlags?: string[];
}

const FraudLogSchema: Schema = new Schema(
  {
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
    },
    amount: {
      type: Number,
      required: true,
    },
    ip: {
      type: String,
      required: true,
    },
    deviceFingerprint: {
      type: String,
      required: true,
    },
    score: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    riskLevel: {
      type: String,
      required: true,
      enum: ['low', 'moderate', 'high'],
    },
    reason: {
      type: String,
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    llmEnhanced: {
      type: Boolean,
      default: false,
    },
    llmFlags: {
      type: [String],
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

// Index for faster queries on commonly accessed fields
FraudLogSchema.index({ riskLevel: 1 });
FraudLogSchema.index({ ip: 1 });
FraudLogSchema.index({ deviceFingerprint: 1 });
FraudLogSchema.index({ email: 1 });
FraudLogSchema.index({ llmEnhanced: 1 });

export default mongoose.model<IFraudLog>('FraudLog', FraudLogSchema); 