import {
  Controller,
  Post,
  Get,
  Put,
  Body,
  Param,
  Headers,
  UseGuards,
  HttpException,
  HttpStatus,
  Logger,
  Query,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { 
  AccessControlService, 
  CreateAccessControlRequest, 
  UpdateAccessControlRequest,
  ValidateAccessRequest 
} from './access-control.service';
import { AuthGuard, CurrentUser } from '../auth/auth.guard';

@Controller('access-control')
export class AccessControlController {
  private readonly logger = new Logger(AccessControlController.name);

  constructor(private readonly accessControlService: AccessControlService) {}

  /**
   * Create access control rules for a file
   * POST /access-control
   */
  @Post()
  @UseGuards(AuthGuard)
  async createAccessControl(
    @Headers('authorization') authorization: string,
    @Body() request: CreateAccessControlRequest,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.accessControlService.createAccessControl(token, request);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          transactionDigest: result.transactionDigest,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to create access control', error);
      throw new HttpException(
        error.message || 'Failed to create access control',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Update access control rules for a file
   * PUT /access-control
   */
  @Put()
  @UseGuards(AuthGuard)
  async updateAccessControl(
    @Headers('authorization') authorization: string,
    @Body() request: UpdateAccessControlRequest,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.accessControlService.updateAccessControl(token, request);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          transactionDigest: result.transactionDigest,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to update access control', error);
      throw new HttpException(
        error.message || 'Failed to update access control',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Create access control rules for a file (Wallet-based auth)
   * POST /access-control/wallet
   */
  @Post('wallet')
  async createAccessControlWithWallet(
    @Headers('x-wallet-address') walletAddress: string,
    @Body() request: CreateAccessControlRequest,
  ) {
    try {
      if (!walletAddress) {
        throw new HttpException('Wallet address required', HttpStatus.BAD_REQUEST);
      }

      const result = await this.accessControlService.createAccessControlWithWallet(walletAddress, request);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          transactionDigest: result.transactionDigest,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to create access control with wallet', error);
      throw new HttpException(
        error.message || 'Failed to create access control',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Update access control rules for a file (Wallet-based auth)
   * PUT /access-control/wallet
   */
  @Put('wallet')
  async updateAccessControlWithWallet(
    @Headers('x-wallet-address') walletAddress: string,
    @Body() request: UpdateAccessControlRequest,
  ) {
    try {
      if (!walletAddress) {
        throw new HttpException('Wallet address required', HttpStatus.BAD_REQUEST);
      }

      const result = await this.accessControlService.updateAccessControlWithWallet(walletAddress, request);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          transactionDigest: result.transactionDigest,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to update access control with wallet', error);
      throw new HttpException(
        error.message || 'Failed to update access control',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Validate access to a file
   * POST /access-control/validate
   */
  @Post('validate')
  @UseGuards(AuthGuard)
  async validateAccess(
    @Headers('authorization') authorization: string,
    @Body() request: ValidateAccessRequest,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.accessControlService.validateAccess(token, request);

      return {
        success: result.success,
        data: {
          accessGranted: result.accessGranted,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to validate access', error);
      throw new HttpException(
        error.message || 'Failed to validate access',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get access control information for a file
   * GET /access-control/:fileCid
   */
  @Get(':fileCid')
  @UseGuards(AuthGuard)
  async getAccessControlInfo(
    @Param('fileCid') fileCid: string,
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.accessControlService.getAccessControlInfo(token, fileCid);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.NOT_FOUND);
      }

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to get access control info', error);
      throw new HttpException(
        'Failed to get access control info',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get access control information for a file (Wallet-based auth)
   * GET /access-control/:fileCid-wallet
   */
  @Get(':fileCid-wallet')
  async getAccessControlInfoWithWallet(
    @Param('fileCid') fileCid: string,
    @Headers('x-wallet-address') walletAddress: string,
  ) {
    try {
      if (!walletAddress) {
        throw new HttpException('Wallet address required', HttpStatus.BAD_REQUEST);
      }

      const result = await this.accessControlService.getAccessControlInfoWithWallet(walletAddress, fileCid);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.NOT_FOUND);
      }

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to get access control info with wallet', error);
      throw new HttpException(
        'Failed to get access control info',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Check if current user can access a file (without recording access)
   * GET /access-control/:fileCid/check
   */
  @Get(':fileCid/check')
  @UseGuards(AuthGuard)
  async checkAccess(
    @Param('fileCid') fileCid: string,
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      
      // Get user info from token
      const userInfo = await this.accessControlService['authService'].verifyToken(token);
      if (!userInfo) {
        throw new HttpException('Authentication failed', HttpStatus.UNAUTHORIZED);
      }

      const request: ValidateAccessRequest = {
        fileCid,
        userAddress: 'zkLoginAddress' in userInfo ? userInfo.zkLoginAddress : userInfo.walletAddress,
        userEmail: 'email' in userInfo ? userInfo.email : undefined,
      };

      const result = await this.accessControlService.validateAccess(token, request);

      return {
        success: result.success,
        data: {
          accessGranted: result.accessGranted,
          userAddress: 'zkLoginAddress' in userInfo ? userInfo.zkLoginAddress : userInfo.walletAddress,
          userEmail: 'email' in userInfo ? userInfo.email : undefined,
        },
        message: result.message,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to check access', error);
      throw new HttpException(
        'Failed to check access',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  // ===== NO-AUTH ENDPOINTS FOR TESTING =====

  /**
   * Create access control without authentication (for testing)
   * POST /access-control/test
   */
  @Post('test')
  async createAccessControlTest(
    @Body() request: CreateAccessControlRequest
  ) {
    try {
      this.logger.log('Creating access control (test mode)');
      
      // For testing, we'll simulate success without actual smart contract interaction
      return {
        success: true,
        data: {
          transactionDigest: `test_tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        },
        message: 'Access control created successfully (test mode)',
      };
    } catch (error) {
      this.logger.error('Failed to create access control (test)', error);
      throw new HttpException(
        error.message || 'Failed to create access control',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Validate access without authentication (for testing)
   * POST /access-control/validate-test
   */
  @Post('validate-test')
  async validateAccessTest(
    @Body() request: ValidateAccessRequest
  ) {
    try {
      this.logger.log('Validating access (test mode)');
      
      // For testing, we'll simulate access granted
      return {
        success: true,
        data: {
          accessGranted: true,
        },
        message: 'Access granted (test mode)',
      };
    } catch (error) {
      this.logger.error('Failed to validate access (test)', error);
      throw new HttpException(
        error.message || 'Failed to validate access',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get access control info without authentication (for testing)
   * GET /access-control/:fileCid/test
   */
  @Get(':fileCid/test')
  async getAccessControlInfoTest(
    @Param('fileCid') fileCid: string
  ) {
    try {
      this.logger.log(`Getting access control info (test mode) for file: ${fileCid}`);

      // Return mock access control info
      return {
        success: true,
        data: {
          fileCid,
          owner: 'test-owner',
          conditionType: 'hybrid',
          allowedEmails: ['test@example.com'],
          allowedAddresses: ['0x1234567890abcdef'],
          accessStartTime: Date.now(),
          accessEndTime: Date.now() + 86400000, // 24 hours from now
          requireAllConditions: false,
          currentAccessCount: 0,
          totalUserRecords: 0,
        },
        message: 'Access control information retrieved successfully (test mode)',
      };
    } catch (error) {
      this.logger.error('Failed to get access control info (test)', error);
      throw new HttpException(
        'Failed to get access control info',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Generate a shareable link for a file
   * POST /access-control/share-link
   */
  @Post('share-link')
  @UseGuards(AuthGuard)
  async generateShareLink(
    @Headers('authorization') authorization: string,
    @Body() request: { fileCid: string; expirationTime?: number; maxUses?: number },
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.accessControlService.generateShareLink(token, request);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to generate share link', error);
      throw new HttpException(
        error.message || 'Failed to generate share link',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Generate a shareable link for a file (test mode)
   * POST /access-control/share-link-test
   */
  @Post('share-link-test')
  async generateShareLinkTest(
    @Body() request: { fileCid: string; expirationTime?: number; maxUses?: number }
  ) {
    try {
      const result = await this.accessControlService.generateShareLinkTest(request);

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to generate share link (test)', error);
      throw new HttpException(
        error.message || 'Failed to generate share link',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Generate a shareable link for a file (Wallet-based auth)
   * POST /access-control/share-link-wallet
   */
  @Post('share-link-wallet')
  async generateShareLinkWithWallet(
    @Headers('x-wallet-address') walletAddress: string,
    @Body() request: { fileCid: string; expirationTime?: number; maxUses?: number },
  ) {
    try {
      if (!walletAddress) {
        throw new HttpException('Wallet address required', HttpStatus.BAD_REQUEST);
      }

      const result = await this.accessControlService.generateShareLinkWithWallet(walletAddress, request);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to generate share link with wallet', error);
      throw new HttpException(
        error.message || 'Failed to generate share link',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Access a file via share link
   * GET /access-control/share/:shareId
   */
  @Get('share/:shareId')
  async accessViaShareLink(
    @Param('shareId') shareId: string,
    @Query('token') token?: string
  ) {
    try {
      const result = await this.accessControlService.validateShareLink(shareId, token);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.FORBIDDEN);
      }

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to access via share link', error);
      throw new HttpException(
        error.message || 'Failed to access file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Process bulk upload data (CSV/Excel)
   * POST /access-control/bulk-upload
   */
  @Post('bulk-upload')
  @UseGuards(AuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  async processBulkUpload(
    @Headers('authorization') authorization: string,
    @UploadedFile() file: Express.Multer.File,
    @Body() body: { fileCid: string; conditionType: string },
    @CurrentUser() user: any
  ) {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.accessControlService.processBulkUpload(
        token,
        file,
        body.fileCid,
        body.conditionType as 'email' | 'wallet' | 'hybrid'
      );

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: result.data,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to process bulk upload', error);
      throw new HttpException(
        error.message || 'Failed to process bulk upload',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}
