import { Injectable, Logger } from '@nestjs/common';
import { SuiService } from '../sui/sui.service';
import { AuthService } from '../auth/auth.service';
import { isValidSuiAddress, normalizeSuiAddress } from '@mysten/sui/utils';

export interface AccessControlRule {
  conditionType: 'email' | 'wallet' | 'time' | 'hybrid';
  allowedEmails?: string[];
  allowedAddresses?: string[];
  allowedSuiNS?: string[];
  accessStartTime?: number;
  accessEndTime?: number;
  maxAccessDuration?: number;
  requireAllConditions?: boolean;
  maxAccessCount?: number;
}

export interface CreateAccessControlRequest {
  fileCid: string;
  accessRule: AccessControlRule;
}

export interface UpdateAccessControlRequest {
  fileCid: string;
  accessRule: AccessControlRule;
}

export interface ValidateAccessRequest {
  fileCid: string;
  userAddress: string;
  userEmail?: string;
}

export interface AccessControlResponse {
  success: boolean;
  message: string;
  transactionDigest?: string;
  accessGranted?: boolean;
  accessControlId?: string;
}

export interface AccessControlInfo {
  fileCid: string;
  owner: string;
  conditionType: string;
  allowedEmails: string[];
  allowedAddresses: string[];
  accessStartTime?: number;
  accessEndTime?: number;
  requireAllConditions: boolean;
  currentAccessCount: number;
  totalUserRecords: number;
}

@Injectable()
export class AccessControlService {
  private readonly logger = new Logger(AccessControlService.name);

  // In-memory storage for share links (in production, this should be a database)
  private shareLinks: Map<string, {
    shareId: string;
    fileCid: string;
    createdBy: string;
    createdAt: number;
    expirationTime?: number;
    maxUses?: number;
    currentUses: number;
  }> = new Map();

  constructor(
    private readonly suiService: SuiService,
    private readonly authService: AuthService
  ) {}

  /**
   * Create access control rules for a file
   */
  async createAccessControl(
    token: string,
    request: CreateAccessControlRequest
  ): Promise<AccessControlResponse> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      this.logger.log(`Creating access control for file ${request.fileCid} by ${userAddress}`);

      // Validate access rule
      const validationResult = this.validateAccessRule(request.accessRule);
      if (!validationResult.valid) {
        return {
          success: false,
          message: `Invalid access rule: ${validationResult.error}`,
        };
      }

      // Create access control on smart contract
      const transactionDigest = await this.suiService.createFileAccessControl(
        userAddress,
        request.fileCid,
        request.accessRule
      );

      this.logger.log(`Access control created for file ${request.fileCid}: ${transactionDigest}`);

      return {
        success: true,
        message: 'Access control created successfully',
        transactionDigest,
      };
    } catch (error) {
      this.logger.error('Failed to create access control', error);
      return {
        success: false,
        message: `Failed to create access control: ${error.message}`,
      };
    }
  }

  /**
   * Update access control rules for a file
   */
  async updateAccessControl(
    token: string,
    request: UpdateAccessControlRequest
  ): Promise<AccessControlResponse> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      this.logger.log(`Updating access control for file ${request.fileCid} by ${userAddress}`);

      // Validate access rule
      const validationResult = this.validateAccessRule(request.accessRule);
      if (!validationResult.valid) {
        return {
          success: false,
          message: `Invalid access rule: ${validationResult.error}`,
        };
      }

      // Update access control on smart contract
      const transactionDigest = await this.suiService.updateFileAccessControl(
        userAddress,
        request.fileCid,
        request.accessRule
      );

      this.logger.log(`Access control updated for file ${request.fileCid}: ${transactionDigest}`);

      return {
        success: true,
        message: 'Access control updated successfully',
        transactionDigest,
      };
    } catch (error) {
      this.logger.error('Failed to update access control', error);
      return {
        success: false,
        message: `Failed to update access control: ${error.message}`,
      };
    }
  }

  /**
   * Create access control rules for a file (Wallet-based auth)
   */
  async createAccessControlWithWallet(
    walletAddress: string,
    request: CreateAccessControlRequest
  ): Promise<AccessControlResponse> {
    try {
      if (!walletAddress) {
        return {
          success: false,
          message: 'Wallet address required',
        };
      }

      this.logger.log(`Creating access control for file ${request.fileCid} by wallet ${walletAddress}`);

      // Validate access rule
      const validationResult = this.validateAccessRule(request.accessRule);
      if (!validationResult.valid) {
        return {
          success: false,
          message: `Invalid access rule: ${validationResult.error}`,
        };
      }

      // Create access control on smart contract
      const transactionDigest = await this.suiService.createFileAccessControl(
        walletAddress,
        request.fileCid,
        request.accessRule
      );

      this.logger.log(`Access control created for file ${request.fileCid}: ${transactionDigest}`);

      return {
        success: true,
        message: 'Access control created successfully',
        transactionDigest,
      };
    } catch (error) {
      this.logger.error('Failed to create access control with wallet', error);
      return {
        success: false,
        message: `Failed to create access control: ${error.message}`,
      };
    }
  }

  /**
   * Update access control rules for a file (Wallet-based auth)
   */
  async updateAccessControlWithWallet(
    walletAddress: string,
    request: UpdateAccessControlRequest
  ): Promise<AccessControlResponse> {
    try {
      if (!walletAddress) {
        return {
          success: false,
          message: 'Wallet address required',
        };
      }

      this.logger.log(`Updating access control for file ${request.fileCid} by wallet ${walletAddress}`);

      // Validate access rule
      const validationResult = this.validateAccessRule(request.accessRule);
      if (!validationResult.valid) {
        return {
          success: false,
          message: `Invalid access rule: ${validationResult.error}`,
        };
      }

      // Update access control on smart contract
      const transactionDigest = await this.suiService.updateFileAccessControl(
        walletAddress,
        request.fileCid,
        request.accessRule
      );

      this.logger.log(`Access control updated for file ${request.fileCid}: ${transactionDigest}`);

      return {
        success: true,
        message: 'Access control updated successfully',
        transactionDigest,
      };
    } catch (error) {
      this.logger.error('Failed to update access control with wallet', error);
      return {
        success: false,
        message: `Failed to update access control: ${error.message}`,
      };
    }
  }

  /**
   * Validate if a user has access to a file
   */
  async validateAccess(
    token: string,
    request: ValidateAccessRequest
  ): Promise<AccessControlResponse> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
          accessGranted: false,
        };
      }

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      const userEmail = 'zkLoginAddress' in user ? (user.email || '') : '';
      
      this.logger.log(`Validating access for file ${request.fileCid} by ${userAddress}`);

      // Check access through smart contract
      const accessGranted = await this.suiService.validateFileAccess(
        request.fileCid,
        request.userAddress || userAddress,
        request.userEmail || userEmail
      );

      this.logger.log(`Access validation result for file ${request.fileCid}: ${accessGranted}`);

      return {
        success: true,
        message: accessGranted ? 'Access granted' : 'Access denied',
        accessGranted,
      };
    } catch (error) {
      this.logger.error('Failed to validate access', error);
      return {
        success: false,
        message: `Failed to validate access: ${error.message}`,
        accessGranted: false,
      };
    }
  }

  /**
   * Get access control information for a file
   */
  async getAccessControlInfo(
    token: string,
    fileCid: string
  ): Promise<{ success: boolean; data?: AccessControlInfo; message: string }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      this.logger.log(`Getting access control info for file ${fileCid}`);

      // Get access control info from smart contract
      const accessControlInfo = await this.suiService.getFileAccessControlInfo(fileCid);

      if (!accessControlInfo) {
        return {
          success: false,
          message: 'Access control not found for this file',
        };
      }

      return {
        success: true,
        data: accessControlInfo,
        message: 'Access control information retrieved successfully',
      };
    } catch (error) {
      this.logger.error('Failed to get access control info', error);
      return {
        success: false,
        message: `Failed to get access control info: ${error.message}`,
      };
    }
  }

  /**
   * Get access control information for a file (Wallet-based auth)
   */
  async getAccessControlInfoWithWallet(
    walletAddress: string,
    fileCid: string
  ): Promise<{ success: boolean; data?: AccessControlInfo; message: string }> {
    try {
      if (!walletAddress) {
        return {
          success: false,
          message: 'Wallet address required',
        };
      }

      this.logger.log(`Getting access control info for file ${fileCid} by wallet ${walletAddress}`);

      // Get access control info from smart contract
      const accessControlInfo = await this.suiService.getFileAccessControlInfo(fileCid);

      if (!accessControlInfo) {
        return {
          success: false,
          message: 'Access control not found for this file',
        };
      }

      return {
        success: true,
        data: accessControlInfo,
        message: 'Access control information retrieved successfully',
      };
    } catch (error) {
      this.logger.error('Failed to get access control info with wallet', error);
      return {
        success: false,
        message: `Failed to get access control info: ${error.message}`,
      };
    }
  }

  /**
   * Validate access rule structure and constraints
   */
  private validateAccessRule(rule: AccessControlRule): { valid: boolean; error?: string } {
    // Check condition type
    if (!['email', 'wallet', 'time', 'hybrid'].includes(rule.conditionType)) {
      return { valid: false, error: 'Invalid condition type' };
    }

    // Validate email addresses
    if (rule.allowedEmails && rule.allowedEmails.length > 0) {
      for (const email of rule.allowedEmails) {
        if (!this.isValidEmail(email)) {
          return { valid: false, error: `Invalid email address: ${email}` };
        }
      }
    }

    // Validate wallet addresses
    if (rule.allowedAddresses && rule.allowedAddresses.length > 0) {
      for (let i = 0; i < rule.allowedAddresses.length; i++) {
        const address = rule.allowedAddresses[i];
        if (!isValidSuiAddress(address)) {
          return { valid: false, error: `Invalid Sui address: ${address}` };
        }
        // Normalize the address to full format
        rule.allowedAddresses[i] = normalizeSuiAddress(address);
      }
    }

    // Validate SuiNS names
    if (rule.allowedSuiNS && rule.allowedSuiNS.length > 0) {
      for (const suiNS of rule.allowedSuiNS) {
        if (!this.isValidSuiNS(suiNS)) {
          return { valid: false, error: `Invalid SuiNS name: ${suiNS}` };
        }
      }
    }

    // Validate time constraints
    if (rule.accessStartTime && rule.accessEndTime) {
      if (rule.accessStartTime >= rule.accessEndTime) {
        return { valid: false, error: 'Access start time must be before end time' };
      }
    }

    if (rule.maxAccessDuration && rule.maxAccessDuration <= 0) {
      return { valid: false, error: 'Max access duration must be positive' };
    }

    if (rule.maxAccessCount && rule.maxAccessCount <= 0) {
      return { valid: false, error: 'Max access count must be positive' };
    }

    // Ensure at least one access method is specified for hybrid type
    if (rule.conditionType === 'hybrid') {
      const hasEmail = rule.allowedEmails && rule.allowedEmails.length > 0;
      const hasAddress = rule.allowedAddresses && rule.allowedAddresses.length > 0;
      const hasSuiNS = rule.allowedSuiNS && rule.allowedSuiNS.length > 0;
      const hasTime = rule.accessStartTime || rule.accessEndTime || rule.maxAccessDuration;

      if (!hasEmail && !hasAddress && !hasSuiNS && !hasTime) {
        return { valid: false, error: 'Hybrid access control must specify at least one access method' };
      }
    }

    return { valid: true };
  }

  /**
   * Validate email address format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }



  /**
   * Resolve email to wallet address (if user has linked accounts)
   */
  async resolveEmailToAddress(email: string): Promise<string | null> {
    try {
      // This would integrate with your user database to find linked wallet addresses
      // For now, return null as this requires additional user management infrastructure
      this.logger.log(`Email to address resolution not implemented for: ${email}`);
      return null;
    } catch (error) {
      this.logger.error('Failed to resolve email to address', error);
      return null;
    }
  }

  /**
   * Generate a shareable link for a file
   */
  async generateShareLink(
    token: string,
    request: { fileCid: string; expirationTime?: number; maxUses?: number }
  ): Promise<{ success: boolean; data?: any; message: string }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      // Check if user owns the file or has permission to create share links
      // This would typically check the smart contract for file ownership
      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      this.logger.log(`Generating share link for file ${request.fileCid} by ${userAddress}`);

      // Generate unique share ID that includes the file CID for recovery
      // Format: share_{timestamp}_{fileCid}_{random}
      const timestamp = Date.now();
      const randomSuffix = Math.random().toString(36).substring(2, 8);
      const shareId = `share_${timestamp}_${request.fileCid}_${randomSuffix}`;

      // Create share link URL
      const shareLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/share/${shareId}`;

      // Store share link data (in a real implementation, this would be stored in a database)
      const shareData = {
        shareId,
        fileCid: request.fileCid,
        createdBy: userAddress,
        createdAt: Date.now(),
        expirationTime: request.expirationTime,
        maxUses: request.maxUses,
        currentUses: 0,
      };

      // Store the share link data in memory
      this.shareLinks.set(shareId, shareData);

      this.logger.log(`Share link created: ${shareId} for file ${request.fileCid}`);

      return {
        success: true,
        data: {
          shareLink,
          shareId,
          expirationTime: request.expirationTime,
          maxUses: request.maxUses,
        },
        message: 'Share link generated successfully',
      };
    } catch (error) {
      this.logger.error('Failed to generate share link', error);
      return {
        success: false,
        message: `Failed to generate share link: ${error.message}`,
      };
    }
  }

  /**
   * Generate a shareable link for a file (Wallet-based auth)
   */
  async generateShareLinkWithWallet(
    walletAddress: string,
    request: { fileCid: string; expirationTime?: number; maxUses?: number }
  ): Promise<{ success: boolean; data?: any; message: string }> {
    try {
      if (!walletAddress) {
        return {
          success: false,
          message: 'Wallet address required',
        };
      }

      this.logger.log(`Generating share link for file ${request.fileCid} by wallet ${walletAddress}`);

      // Generate unique share ID that includes the file CID for recovery
      // Format: share_{timestamp}_{fileCid}_{random}
      const timestamp = Date.now();
      const randomSuffix = Math.random().toString(36).substring(2, 8);
      const shareId = `share_${timestamp}_${request.fileCid}_${randomSuffix}`;

      // Create share link URL
      const shareLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/share/${shareId}`;

      // Store share link data (in a real implementation, this would be stored in a database)
      const shareData = {
        shareId,
        fileCid: request.fileCid,
        createdBy: walletAddress,
        createdAt: Date.now(),
        expirationTime: request.expirationTime,
        maxUses: request.maxUses,
        currentUses: 0,
      };

      // Store the share link data in memory
      this.shareLinks.set(shareId, shareData);

      this.logger.log(`Share link created: ${shareId} for file ${request.fileCid}`);

      return {
        success: true,
        data: {
          shareLink,
          shareId,
          expirationTime: request.expirationTime,
          maxUses: request.maxUses,
        },
        message: 'Share link generated successfully',
      };
    } catch (error) {
      this.logger.error('Failed to generate share link with wallet', error);
      return {
        success: false,
        message: `Failed to generate share link: ${error.message}`,
      };
    }
  }

  /**
   * Generate a shareable link for a file (test mode)
   */
  async generateShareLinkTest(
    request: { fileCid: string; expirationTime?: number; maxUses?: number }
  ): Promise<{ success: boolean; data?: any; message: string }> {
    try {
      this.logger.log(`Generating share link (test mode) for file ${request.fileCid}`);

      // Generate unique share ID that includes the file CID for recovery
      // Format: test_share_{timestamp}_{fileCid}_{random}
      const timestamp = Date.now();
      const randomSuffix = Math.random().toString(36).substring(2, 8);
      const shareId = `test_share_${timestamp}_${request.fileCid}_${randomSuffix}`;

      // Create share link URL
      const shareLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/share/${shareId}`;

      // Store share link data for test mode
      const shareData = {
        shareId,
        fileCid: request.fileCid,
        createdBy: 'test-user',
        createdAt: Date.now(),
        expirationTime: request.expirationTime,
        maxUses: request.maxUses,
        currentUses: 0,
      };

      // Store the share link data in memory
      this.shareLinks.set(shareId, shareData);

      this.logger.log(`Test share link created: ${shareId} for file ${request.fileCid}`);

      return {
        success: true,
        data: {
          shareLink,
          shareId,
          expirationTime: request.expirationTime,
          maxUses: request.maxUses,
        },
        message: 'Share link generated successfully (test mode)',
      };
    } catch (error) {
      this.logger.error('Failed to generate share link (test)', error);
      return {
        success: false,
        message: `Failed to generate share link: ${error.message}`,
      };
    }
  }

  /**
   * Validate a share link and return file access information
   */
  async validateShareLink(
    shareId: string,
    token?: string
  ): Promise<{ success: boolean; data?: any; message: string }> {
    try {
      this.logger.log(`Validating share link: ${shareId}`);

      // Check if share link exists and is valid
      if (!shareId.startsWith('share_') && !shareId.startsWith('test_share_')) {
        return {
          success: false,
          message: 'Invalid share link',
        };
      }

      // Look up the share link in our storage
      let shareData = this.shareLinks.get(shareId);

      // If not found in memory, try to extract file CID from share ID
      // This allows recovery even after server restarts
      if (!shareData) {
        this.logger.warn(`Share link ${shareId} not found in memory, attempting to extract file CID`);

        // Try to extract file CID from share ID format
        // Format: share_{timestamp}_{fileCid}_{random} or test_share_{timestamp}_{fileCid}_{random}
        let extractedFileCid: string | null = null;

        if (shareId.startsWith('share_')) {
          const parts = shareId.split('_');
          if (parts.length >= 4) {
            // parts[0] = 'share', parts[1] = timestamp, parts[2] = fileCid, parts[3] = random
            extractedFileCid = parts[2];
          }
        } else if (shareId.startsWith('test_share_')) {
          const parts = shareId.split('_');
          if (parts.length >= 5) {
            // parts[0] = 'test', parts[1] = 'share', parts[2] = timestamp, parts[3] = fileCid, parts[4] = random
            extractedFileCid = parts[3];
          }
        }

        if (extractedFileCid) {
          this.logger.log(`Extracted file CID from share ID: ${extractedFileCid}`);

          // Create a temporary share data entry with the extracted file CID
          shareData = {
            shareId,
            fileCid: extractedFileCid,
            createdBy: 'recovered',
            createdAt: Date.now() - 3600000, // 1 hour ago
            expirationTime: Date.now() + 86400000, // 24 hours from now
            maxUses: 100,
            currentUses: 0,
          };

          // Store it for future use
          this.shareLinks.set(shareId, shareData);

          this.logger.log(`Created recovered share data for ${shareId} with file CID: ${extractedFileCid}`);
        } else {
          return {
            success: false,
            message: 'Share link not found or has expired',
          };
        }
      }

      // Check expiration
      if (shareData.expirationTime && Date.now() > shareData.expirationTime) {
        return {
          success: false,
          message: 'Share link has expired',
        };
      }

      // Check usage limit
      if (shareData.maxUses && shareData.currentUses >= shareData.maxUses) {
        return {
          success: false,
          message: 'Share link usage limit exceeded',
        };
      }

      // Note: Smart contract doesn't have get_file_metadata function
      // We'll get the filename from the stored share data or use a default
      let filename = 'shared-file';
      let isEncrypted = false;
      let fileSize: number | undefined;

      // The filename should be available from when the share link was created
      // But let's also try to look it up from the file service if needed
      this.logger.log(`Share link validation for ${shareData.fileCid}, stored share data:`, shareData);

      // Increment usage count (in real implementation, this would be persisted)
      shareData.currentUses++;

      return {
        success: true,
        data: {
          fileCid: shareData.fileCid,
          accessGranted: true,
          filename, // Will be looked up properly in downloadSharedFile
          fileSize,
          contentType: 'application/octet-stream', // Default content type
          isEncrypted, // Will be determined properly in downloadSharedFile
        },
        message: 'Share link validated successfully',
      };
    } catch (error) {
      this.logger.error('Failed to validate share link', error);
      return {
        success: false,
        message: `Failed to validate share link: ${error.message}`,
      };
    }
  }

  /**
   * Process bulk upload data from CSV/Excel files
   */
  async processBulkUpload(
    token: string,
    file: Express.Multer.File,
    fileCid: string,
    conditionType: 'email' | 'wallet' | 'hybrid'
  ): Promise<{ success: boolean; data?: any; message: string }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      this.logger.log(`Processing bulk upload for file ${fileCid} by ${userAddress}`);

      // Validate file type
      const allowedMimeTypes = [
        'text/csv',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      ];

      if (!allowedMimeTypes.includes(file.mimetype)) {
        return {
          success: false,
          message: 'Invalid file type. Only CSV and Excel files are supported.',
        };
      }

      // Parse file content
      const fileContent = file.buffer.toString('utf-8');
      const parsedData = this.parseBulkData(fileContent, file.mimetype);

      if (parsedData.errors.length > 0) {
        return {
          success: false,
          message: `Validation errors: ${parsedData.errors.join(', ')}`,
          data: { errors: parsedData.errors },
        };
      }

      // Create access control rule from parsed data
      const accessRule: AccessControlRule = {
        conditionType,
        allowedEmails: parsedData.emails.length > 0 ? parsedData.emails : undefined,
        allowedAddresses: parsedData.addresses.length > 0 ? parsedData.addresses : undefined,
        allowedSuiNS: parsedData.suiNSNames.length > 0 ? parsedData.suiNSNames : undefined,
      };

      // Validate the access rule
      const validation = this.validateAccessRule(accessRule);
      if (!validation.valid) {
        return {
          success: false,
          message: validation.error || 'Invalid access rule',
        };
      }

      // Update access control with bulk data
      const updateResult = await this.updateAccessControl(token, {
        fileCid,
        accessRule,
      });

      if (!updateResult.success) {
        return {
          success: false,
          message: updateResult.message,
        };
      }

      return {
        success: true,
        data: {
          processed: {
            emails: parsedData.emails.length,
            addresses: parsedData.addresses.length,
            suiNSNames: parsedData.suiNSNames.length,
          },
          transactionDigest: updateResult.transactionDigest,
        },
        message: `Bulk upload processed successfully. Added ${parsedData.emails.length} emails, ${parsedData.addresses.length} addresses, and ${parsedData.suiNSNames.length} SuiNS names.`,
      };
    } catch (error) {
      this.logger.error('Failed to process bulk upload', error);
      return {
        success: false,
        message: `Failed to process bulk upload: ${error.message}`,
      };
    }
  }

  /**
   * Parse bulk data from file content
   */
  private parseBulkData(
    content: string,
    mimeType: string
  ): { emails: string[]; addresses: string[]; suiNSNames: string[]; errors: string[] } {
    const result = {
      emails: [] as string[],
      addresses: [] as string[],
      suiNSNames: [] as string[],
      errors: [] as string[],
    };

    try {
      let lines: string[] = [];

      if (mimeType === 'text/csv') {
        // Parse CSV
        lines = content.split('\n').map(line => line.trim()).filter(line => line);
      } else {
        // For Excel files, we'd need a proper Excel parser
        // For now, treat as CSV (this would need xlsx library in production)
        lines = content.split('\n').map(line => line.trim()).filter(line => line);
      }

      // Skip header row if it exists
      const hasHeader = lines.length > 0 && (
        lines[0].toLowerCase().includes('email') ||
        lines[0].toLowerCase().includes('address') ||
        lines[0].toLowerCase().includes('suins')
      );

      const dataLines = hasHeader ? lines.slice(1) : lines;

      for (const line of dataLines) {
        if (!line) continue;

        // Split by comma for CSV
        const values = line.split(',').map(v => v.trim().replace(/"/g, ''));

        for (const value of values) {
          if (!value) continue;

          // Determine type and validate
          if (this.isValidEmail(value)) {
            if (!result.emails.includes(value)) {
              result.emails.push(value);
            }
          } else if (isValidSuiAddress(value)) {
            if (!result.addresses.includes(value)) {
              result.addresses.push(value);
            }
          } else if (this.isValidSuiNS(value)) {
            if (!result.suiNSNames.includes(value)) {
              result.suiNSNames.push(value);
            }
          } else {
            result.errors.push(`Invalid format: ${value}`);
          }
        }
      }

      // Limit the number of entries to prevent abuse
      const maxEntries = 1000;
      if (result.emails.length > maxEntries) {
        result.errors.push(`Too many emails (max ${maxEntries})`);
        result.emails = result.emails.slice(0, maxEntries);
      }
      if (result.addresses.length > maxEntries) {
        result.errors.push(`Too many addresses (max ${maxEntries})`);
        result.addresses = result.addresses.slice(0, maxEntries);
      }
      if (result.suiNSNames.length > maxEntries) {
        result.errors.push(`Too many SuiNS names (max ${maxEntries})`);
        result.suiNSNames = result.suiNSNames.slice(0, maxEntries);
      }

    } catch (error) {
      result.errors.push(`Failed to parse file: ${error.message}`);
    }

    return result;
  }

  /**
   * Validate SuiNS name format
   */
  private isValidSuiNS(name: string): boolean {
    // SuiNS names should end with .sui and contain valid characters
    const suiNSRegex = /^[a-zA-Z0-9-_]+\.sui$/;
    return suiNSRegex.test(name);
  }
}
