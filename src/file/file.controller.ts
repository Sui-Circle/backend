import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Headers,
  UseGuards,
  HttpException,
  HttpStatus,
  Logger,
  UseInterceptors,
  UploadedFile,
  Res,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { Response } from 'express';
import { Multer } from 'multer';
import { FileService, FileUploadRequest, FileAccessRequest } from './file.service';
import { AuthGuard, CurrentUser } from '../auth/auth.guard';

@Controller('file')
export class FileController {
  private readonly logger = new Logger(FileController.name);

  constructor(private readonly fileService: FileService) {}

  /**
   * Upload a file with multipart form data (Token-based auth)
   * POST /file/upload
   */
  @Post('upload')
  @UseGuards(AuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  async uploadFile(
    @Headers('authorization') authorization: string,
    @Headers('x-walrus-epochs') epochsHeader: string,
    @Headers('x-walrus-deletable') deletableHeader: string,
    @UploadedFile() file: Express.Multer.File,
    @CurrentUser() user: any
  ) {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      const uploadRequest: FileUploadRequest = {
        filename: file.originalname,
        fileSize: file.size,
        contentType: file.mimetype,
        fileData: file.buffer,
        walrusOptions: {
          epochs: epochsHeader ? parseInt(epochsHeader) : undefined,
          deletable: typeof deletableHeader === 'string' ? deletableHeader.toLowerCase() === 'true' : undefined,
        },
      };

      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.uploadFile(token, uploadRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          fileCid: result.fileCid,
          transactionDigest: result.transactionDigest,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to upload file', error);
      throw new HttpException(
        error.message || 'Failed to upload file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Upload a file with multipart form data (Wallet-based auth)
   * POST /file/upload-wallet
   */
  @Post('upload-wallet')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFileWithWallet(
    @Headers('x-wallet-address') walletAddress: string,
    @Headers('x-walrus-epochs') epochsHeader: string,
    @Headers('x-walrus-deletable') deletableHeader: string,
    @UploadedFile() file: Express.Multer.File,
  ) {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      if (!walletAddress) {
        throw new HttpException('Wallet address is required', HttpStatus.BAD_REQUEST);
      }

      const uploadRequest: FileUploadRequest = {
        filename: file.originalname,
        fileSize: file.size,
        contentType: file.mimetype,
        fileData: file.buffer,
        walrusOptions: {
          epochs: epochsHeader ? parseInt(epochsHeader) : undefined,
          deletable: typeof deletableHeader === 'string' ? deletableHeader.toLowerCase() === 'true' : undefined,
        },
      };

      // For wallet-based auth, we'll use the wallet address as the identifier
      const result = await this.fileService.uploadFileWithWallet(walletAddress, uploadRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          fileCid: result.fileCid,
          transactionDigest: result.transactionDigest,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to upload file with wallet', error);
      throw new HttpException(
        error.message || 'Failed to upload file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Upload a file with JSON body (for pre-uploaded Walrus files)
   * POST /file/upload-metadata
   */
  @Post('upload-metadata')
  @UseGuards(AuthGuard)
  async uploadFileMetadata(
    @Headers('authorization') authorization: string,
    @Body() uploadRequest: FileUploadRequest,
    @CurrentUser() user: any
  ) {
    try {
      // Ensure default Walrus options if client didn't provide them
      uploadRequest.walrusOptions = uploadRequest.walrusOptions || {};
      if (typeof uploadRequest.walrusOptions.deletable === 'undefined') {
        uploadRequest.walrusOptions.deletable = false;
      }
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.uploadFile(token, uploadRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          fileCid: result.fileCid,
          transactionDigest: result.transactionDigest,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to upload file metadata', error);
      throw new HttpException(
        error.message || 'Failed to upload file metadata',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get file metadata
   * GET /file/:cid/info
   */
  @Get(':cid/info')
  @UseGuards(AuthGuard)
  async getFileInfo(
    @Param('cid') cid: string,
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const accessRequest: FileAccessRequest = { fileCid: cid };
      const result = await this.fileService.accessFile(token, accessRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      if (!result.authorized) {
        throw new HttpException(result.message, HttpStatus.FORBIDDEN);
      }

      return {
        success: true,
        data: {
          fileMetadata: result.fileMetadata,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to access file', error);
      throw new HttpException(
        'Failed to access file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Download a file
   * GET /file/:cid/download
   */
  @Get(':cid/download')
  @UseGuards(AuthGuard)
  async downloadFile(
    @Param('cid') cid: string,
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any,
    @Res() res: Response
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.downloadFile(token, cid);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      // Set appropriate headers for file download
      res.setHeader('Content-Type', result.contentType || 'application/octet-stream');
      res.setHeader('Content-Length', result.fileData!.length);

      if (result.filename) {
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      }

      // Add encryption status header if encrypted
      if (result.isEncrypted) {
        res.setHeader('X-File-Encrypted', 'true');
        if ((result as any).encryptionId) {
          res.setHeader('X-Seal-Encryption-Id', (result as any).encryptionId);
        }
        this.logger.warn(`Downloading encrypted file: ${result.filename} - file may need decryption`);
      }

      // Send the file data
      res.send(result.fileData);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to download file', error);
      throw new HttpException(
        'Failed to download file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Grant access to a file
   * POST /file/:cid/grant-access
   */
  @Post(':cid/grant-access')
  @UseGuards(AuthGuard)
  async grantFileAccess(
    @Param('cid') cid: string,
    @Body() body: { recipientAddress: string },
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.grantFileAccess(
        token,
        cid,
        body.recipientAddress
      );

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
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to grant file access', error);
      throw new HttpException(
        'Failed to grant file access',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Revoke access to a file
   * POST /file/:cid/revoke-access
   */
  @Post(':cid/revoke-access')
  @UseGuards(AuthGuard)
  async revokeFileAccess(
    @Param('cid') cid: string,
    @Body() body: { addressToRemove: string },
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.revokeFileAccess(
        token,
        cid,
        body.addressToRemove
      );

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
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to revoke file access', error);
      throw new HttpException(
        'Failed to revoke file access',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * List user's files
   * GET /file
   */
  @Get()
  @UseGuards(AuthGuard)
  async listUserFiles(
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.listUserFiles(token);

      return {
        success: result.success,
        data: {
          files: result.files,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to list user files', error);
      throw new HttpException(
        'Failed to list user files',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  // ===== NO-AUTH ENDPOINTS FOR TESTING =====

  /**
   * Upload a file without authentication (for testing)
   * POST /file/upload-test
   */
  @Post('upload-test')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFileTest(
    @UploadedFile() file: Express.Multer.File,
  ) {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      const uploadRequest: FileUploadRequest = {
        filename: file.originalname,
        fileSize: file.size,
        contentType: file.mimetype,
        fileData: file.buffer,
      };

      const result = await this.fileService.uploadFileNoAuth(uploadRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          fileCid: result.fileCid,
          transactionDigest: result.transactionDigest,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to upload file (test)', error);
      throw new HttpException(
        error.message || 'Failed to upload file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Download a file without authentication (for testing)
   * GET /file/:cid/download-test
   */
  @Get(':cid/download-test')
  async downloadFileTest(
    @Param('cid') cid: string,
    @Res() res: Response
  ) {
    try {
      const result = await this.fileService.downloadFileNoAuth(cid);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      // Set appropriate headers for file download
      res.setHeader('Content-Type', result.contentType || 'application/octet-stream');
      res.setHeader('Content-Length', result.fileData!.length);

      if (result.filename) {
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      }

      // Add encryption status header if encrypted
      if (result.isEncrypted) {
        res.setHeader('X-File-Encrypted', 'true');
        if ((result as any).encryptionId) {
          res.setHeader('X-Seal-Encryption-Id', (result as any).encryptionId);
        }
        this.logger.warn(`Downloading encrypted file: ${result.filename} - file may need decryption`);
      }

      // Send the file data
      res.send(result.fileData);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to download file (test)', error);
      throw new HttpException(
        'Failed to download file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get Walrus service configuration status
   * GET /file/walrus-status
   */
  @Get('walrus-status')
  async getWalrusStatus() {
    try {
      const walrusService = this.fileService['walrusService']; // Access private property
      const status = walrusService.getConfigurationStatus();
      const validation = walrusService.validateConfiguration();

      return {
        success: true,
        data: {
          ...status,
          validation,
          environment: process.env.NODE_ENV || 'development',
        },
        message: 'Walrus configuration status retrieved',
      };
    } catch (error) {
      this.logger.error('Failed to get Walrus status', error);
      throw new HttpException(
        'Failed to get Walrus status',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get wallet information including balances
   * GET /file/wallet-info
   */
  @Get('wallet-info')
  async getWalletInfo() {
    try {
      const walrusService = this.fileService['walrusService']; // Access private property
      const walletInfo = await walrusService.getWalletInfo();

      return {
        success: true,
        data: walletInfo,
        message: 'Wallet information retrieved',
      };
    } catch (error) {
      this.logger.error('Failed to get wallet info', error);
      throw new HttpException(
        'Failed to get wallet info',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Upload an encrypted file with multipart form data
   * POST /file/upload-encrypted
   */
  @Post('upload-encrypted')
  @UseGuards(AuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  async uploadEncryptedFile(
    @Headers('authorization') authorization: string,
    @UploadedFile() file: Express.Multer.File,
    @CurrentUser() user: any
  ) {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      const uploadRequest: FileUploadRequest = {
        filename: file.originalname,
        fileSize: file.size,
        contentType: file.mimetype,
        fileData: file.buffer,
        enableEncryption: true,
      };

      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const result = await this.fileService.uploadFile(token, uploadRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          fileCid: result.fileCid,
          transactionDigest: result.transactionDigest,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to upload encrypted file', error);
      throw new HttpException(
        error.message || 'Failed to upload encrypted file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Download and decrypt an encrypted file
   * POST /file/:cid/download-encrypted
   */
  @Post(':cid/download-encrypted')
  @UseGuards(AuthGuard)
  async downloadEncryptedFile(
    @Param('cid') cid: string,
    @Body() body: { secretKey?: string },
    @Headers('authorization') authorization: string,
    @CurrentUser() user: any,
    @Res() res: Response
  ) {
    try {
      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      
      // For Mysten SEAL encrypted files, try decryption without sessionKey/txBytes
      // as the backend handles the full encryption/decryption cycle
      const result = await this.fileService.downloadAndDecryptSeal(token, cid);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      // Set appropriate headers for file download
      res.setHeader('Content-Type', result.contentType || 'application/octet-stream');
      res.setHeader('Content-Length', result.fileData!.length);

      if (result.filename) {
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      }

      // Send the decrypted file data
      res.send(result.fileData);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to download encrypted file', error);
      throw new HttpException(
        'Failed to download encrypted file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Upload an encrypted file without authentication (for testing)
   * POST /file/upload-encrypted-test
   */
  @Post('upload-encrypted-test')
  @UseInterceptors(FileInterceptor('file'))
  async uploadEncryptedFileTest(
    @UploadedFile() file: Express.Multer.File,
  ) {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      const uploadRequest: FileUploadRequest = {
        filename: file.originalname,
        fileSize: file.size,
        contentType: file.mimetype,
        fileData: file.buffer,
        enableEncryption: true,
      };

      const result = await this.fileService.uploadFileNoAuth(uploadRequest);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        data: {
          fileCid: result.fileCid,
          transactionDigest: result.transactionDigest,
          walrusCid: result.walrusCid,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to upload encrypted file (test)', error);
      throw new HttpException(
        error.message || 'Failed to upload encrypted file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get SEAL encryption service status
   * GET /file/seal-status
   */
  @Get('seal-status')
  async getSealStatus() {
    try {
      const sealService = this.fileService['sealService']; // Access private property

      return {
        success: true,
        data: {
          isReady: sealService.isReady(),
          version: sealService.getVersion(),
        },
        message: 'SEAL encryption service status retrieved',
      };
    } catch (error) {
      this.logger.error('Failed to get SEAL status', error);
      throw new HttpException(
        'Failed to get SEAL status',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * List user's files without authentication (for testing)
   * GET /file/list-test
   */
  @Get('list-test')
  async listUserFilesTest() {
    try {
      const result = await this.fileService.listUserFilesNoAuth();

      return {
        success: result.success,
        files: result.files, // Direct files array for compatibility
        data: {
          files: result.files,
        },
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Failed to list user files (test)', error);
      throw new HttpException(
        'Failed to list user files',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Download a file via share link
   * GET /file/shared/:shareId/download
   */
  @Get('shared/:shareId/download')
  async downloadSharedFile(
    @Param('shareId') shareId: string,
    @Headers('authorization') authorization: string,
    @Res() res: Response
  ) {
    try {
      // Extract token if provided (optional for shared files)
      let token: string | undefined;
      if (authorization && authorization.startsWith('Bearer ')) {
        token = authorization.substring(7);
      }

      const result = await this.fileService.downloadSharedFile(shareId, token);

      if (!result.success) {
        throw new HttpException(result.message, HttpStatus.BAD_REQUEST);
      }

      // Set appropriate headers for file download
      res.setHeader('Content-Type', result.contentType || 'application/octet-stream');
      res.setHeader('Content-Length', result.fileData!.length);

      if (result.filename) {
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      }

      // Add encryption status header
      if (result.isEncrypted) {
        res.setHeader('X-File-Encrypted', 'true');
        if ((result as any).encryptionId) {
          res.setHeader('X-Seal-Encryption-Id', (result as any).encryptionId);
        }
        this.logger.warn(`Downloading encrypted file: ${result.filename} - file may need decryption`);
      }

      // Send the file data
      res.send(Buffer.from(result.fileData!));
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to download shared file', error);
      throw new HttpException(
        'Failed to download shared file',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}
