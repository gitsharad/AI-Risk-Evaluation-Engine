import express, { Request, Response, NextFunction, Router } from 'express';
import { getRiskConfig, updateRiskConfig, loadConfigFromFile } from '../config/config';
import { logger } from '../utils/logger';

const router: Router = express.Router();

/**
 * @route GET /config
 * @desc Get current risk configuration
 * @access Public
 */
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const config = await getRiskConfig();
    
    return res.status(200).json({
      success: true,
      data: config,
    });
  } catch (error) {
    logger.error('Error getting risk configuration:', error);
    next(error);
  }
});

/**
 * @route PUT /config
 * @desc Update risk configuration
 * @access Public
 */
router.put('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const updates = req.body;
    
    if (!updates || Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No update data provided',
      });
    }
    
    const updatedConfig = await updateRiskConfig(updates);
    
    return res.status(200).json({
      success: true,
      message: 'Configuration updated successfully',
      data: updatedConfig,
    });
  } catch (error) {
    logger.error('Error updating risk configuration:', error);
    next(error);
  }
});

/**
 * @route POST /config/import
 * @desc Import configuration from JSON file
 * @access Public
 */
router.post('/import', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { filePath } = req.body;
    
    if (!filePath) {
      return res.status(400).json({
        success: false,
        error: 'File path is required',
      });
    }
    
    const updatedConfig = await loadConfigFromFile(filePath);
    
    return res.status(200).json({
      success: true,
      message: 'Configuration imported successfully',
      data: updatedConfig,
    });
  } catch (error) {
    logger.error('Error importing configuration from file:', error);
    next(error);
  }
});

export default router; 