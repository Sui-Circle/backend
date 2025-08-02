import { Injectable, Logger } from '@nestjs/common';
import { SuiService } from '../sui/sui.service';
import { AuthService } from '../auth/auth.service';
import { WalrusService } from '../storage/walrus/walrus.service';
import { SealService } from '../storage/seal/seal.service';
import { AccessControlService } from '../access-control/access-control.service';
import { WalletValidationService } from '../validation/wallet-validation.service';

export interface FileUploadRequest {
  filename: string;
  fileSize: number;
  contentType: string;
  fileData: Buffer; // Raw file data to upload to Walrus
  walrusCid?: string; // Optional - will be generated if not provided
  enableEncryption?: boolean; // Whether to encrypt the file with SEAL
}

export interface EncryptedFileUploadRequest extends FileUploadRequest {
  enableEncryption: true;
}

export interface EncryptedFileMetadata {
  filename: string;
  fileSize: number;
  uploadTimestamp: number;
  uploader: string;
  isEncrypted: boolean;
  encryptionKeys?: {
    publicKey: string;
    secretKey: string;
  };
}

export interface FileAccessRequest {
  fileCid: string;
  requesterAddress?: string;
}

export interface FileUploadResponse {
  success: boolean;
  fileCid: string;
  transactionDigest: string;
  walrusCid: string;
  message: string;
}

export interface FileAccessResponse {
  success: boolean;
  authorized: boolean;
  fileMetadata?: {
    filename: string;
    fileSize: number;
    uploadTimestamp: number;
    uploader: string;
  };
  walrusCid?: string;
  message: string;
}

@Injectable()
export class FileService {
  private readonly logger = new Logger(FileService.name);

  // In-memory storage for uploaded files (for testing)
  private uploadedFiles: Map<string, Array<{
    cid: string;
    filename: string;
    fileSize: number;
    uploadTimestamp: number;
    uploader: string;
    isOwner: boolean;
    isEncrypted?: boolean;
    encryptionKeys?: {
      publicKey: string;
      secretKey: string;
    };
  }>> = new Map();

  // In-memory storage for test mode files
  private testModeFiles: Array<{
    cid: string;
    filename: string;
    fileSize: number;
    uploadTimestamp: number;
    uploader: string;
    isOwner: boolean;
    isEncrypted?: boolean;
    encryptionKeys?: {
      publicKey: string;
      secretKey: string;
    };
  }> = [];

  constructor(
    private readonly suiService: SuiService,
    private readonly authService: AuthService,
    private readonly walrusService: WalrusService,
    private readonly sealService: SealService,
    private readonly accessControlService: AccessControlService,
    private readonly walletValidationService: WalletValidationService
  ) {}

  /**
   * Upload a file with zkLogin authentication
   */
  async uploadFile(
    token: string,
    uploadRequest: FileUploadRequest
  ): Promise<FileUploadResponse> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          fileCid: '',
          transactionDigest: '',
          walrusCid: uploadRequest.walrusCid || '',
          message: 'Authentication failed',
        };
      }

      // Validate zkLogin authentication
      const validationResult = this.walletValidationService.validateZkLoginAuthentication(user);
      if (!validationResult.isValid) {
        this.logger.error('zkLogin validation failed:', validationResult.errors);
        return {
          success: false,
          fileCid: '',
          transactionDigest: '',
          walrusCid: uploadRequest.walrusCid || '',
          message: `Authentication validation failed: ${validationResult.errors.join(', ')}`,
        };
      }

      // Check for admin address usage
      const adminValidation = this.walletValidationService.validateNoAdminAddressUsage(
        user.zkLoginAddress,
        'file_upload'
      );
      if (!adminValidation.isValid) {
        this.logger.error('Admin address usage detected:', adminValidation.errors);
        return {
          success: false,
          fileCid: '',
          transactionDigest: '',
          walrusCid: uploadRequest.walrusCid || '',
          message: `Invalid wallet usage: ${adminValidation.errors.join(', ')}`,
        };
      }

      let walrusCid = uploadRequest.walrusCid;
      let encryptionKeys: { encryptionId: string; symmetricKey: string } | undefined;
      let dataToUpload = uploadRequest.fileData;

      // Handle encryption if requested
      if (uploadRequest.enableEncryption) {
        this.logger.log(`Encrypting file with SEAL: ${uploadRequest.filename}`);

        // Get package ID from environment or use default
        const packageId = process.env.SUI_PACKAGE_ID || '0x1'; // You'll need to set this

        const encryptionResult = await this.sealService.encryptFile(
          uploadRequest.fileData,
          {
            packageId,
            identity: uploadRequest.filename, // Use filename as identity
            threshold: 3, // Default threshold
          }
        );

        if (!encryptionResult.success) {
          return {
            success: false,
            fileCid: '',
            transactionDigest: '',
            walrusCid: '',
            message: `Failed to encrypt file: ${encryptionResult.error}`,
          };
        }

        dataToUpload = Buffer.from(encryptionResult.encryptedData!);
        encryptionKeys = {
          encryptionId: encryptionResult.encryptionId!,
          symmetricKey: Buffer.from(encryptionResult.symmetricKey!).toString('base64'),
        };

        this.logger.log(`File encrypted successfully: ${uploadRequest.filename}`);
      }

      // If no Walrus CID provided, upload to Walrus first
      if (!walrusCid) {
        this.logger.log(`Uploading file to Walrus: ${uploadRequest.filename}${uploadRequest.enableEncryption ? ' (encrypted)' : ''}`);

        let walrusResult: any;

        // Check if user has zkLogin transaction parameters for signing
        this.logger.log('🔍 Checking zkLogin parameters for user:', {
          hasEphemeralKeyPair: !!user.ephemeralKeyPair,
          hasZkLoginProof: !!user.zkLoginProof,
          hasJwt: !!user.jwt,
          hasUserSalt: !!user.userSalt,
          zkLoginAddress: user.zkLoginAddress,
        });

        if (user.ephemeralKeyPair && user.zkLoginProof && user.jwt && user.userSalt) {
          this.logger.log('✅ Using zkLogin signature for Walrus upload');

          const zkLoginParams = {
            ephemeralKeyPair: user.ephemeralKeyPair,
            zkLoginProof: user.zkLoginProof,
            jwt: user.jwt,
            userSalt: user.userSalt,
          };

          walrusResult = await this.walrusService.uploadFileWithZkLogin(
            dataToUpload,
            uploadRequest.filename,
            zkLoginParams,
            uploadRequest.contentType
          );
        } else {
          this.logger.error('❌ zkLogin parameters not available - cannot upload without user authentication');
          this.logger.error('Missing zkLogin parameters:', {
            missingEphemeralKeyPair: !user.ephemeralKeyPair,
            missingZkLoginProof: !user.zkLoginProof,
            missingJwt: !user.jwt,
            missingUserSalt: !user.userSalt,
          });

          // Do not fallback to admin signer - require proper user authentication
          return {
            success: false,
            fileCid: '',
            transactionDigest: '',
            walrusCid: '',
            message: 'User authentication required: zkLogin parameters missing. Please log in again.',
          };
        }

        if (!walrusResult.success) {
          return {
            success: false,
            fileCid: '',
            transactionDigest: '',
            walrusCid: '',
            message: `Failed to upload to Walrus: ${walrusResult.error}`,
          };
        }

        walrusCid = walrusResult.blobId!;
        this.logger.log(`File uploaded to Walrus with CID: ${walrusCid}`);
      }

      // Ensure walrusCid is defined
      if (!walrusCid) {
        return {
          success: false,
          fileCid: '',
          transactionDigest: '',
          walrusCid: '',
          message: 'Failed to get Walrus CID',
        };
      }

      // Upload file metadata to smart contract with user paying fees
      this.logger.log('User will pay transaction fees for smart contract upload');

      // Check required zkLogin parameters (temporarily allowing without proof for debugging)
      const hasRequiredParams = user.ephemeralKeyPair && user.jwt && user.userSalt;

      this.logger.log('Smart contract upload parameter check:', {
        hasEphemeralKeyPair: !!user.ephemeralKeyPair,
        hasZkLoginProof: !!user.zkLoginProof,
        hasJwt: !!user.jwt,
        hasUserSalt: !!user.userSalt,
        hasRequiredParams,
      });

      if (!hasRequiredParams) {
        this.logger.error('Missing zkLogin parameters for smart contract upload:', {
          missingEphemeralKeyPair: !user.ephemeralKeyPair,
          missingZkLoginProof: !user.zkLoginProof,
          missingJwt: !user.jwt,
          missingUserSalt: !user.userSalt,
        });

        return {
          success: false,
          fileCid: '',
          transactionDigest: '',
          walrusCid,
          message: 'zkLogin parameters missing for transaction signing',
        };
      }

      // Create zkLoginParams with proper type checking
      const zkLoginParams = {
        ephemeralKeyPair: user.ephemeralKeyPair!,
        zkLoginProof: user.zkLoginProof,
        jwt: user.jwt!,
        userSalt: user.userSalt!,
      };

      // Execute transaction with user paying fees
      const transactionDigest = await this.suiService.uploadFileWithZkLogin(
        walrusCid, // Using Walrus CID as file CID
        uploadRequest.filename,
        uploadRequest.fileSize,
        zkLoginParams
      );

      this.logger.log(
        `File metadata uploaded to smart contract: ${uploadRequest.filename} by ${user.zkLoginAddress}`
      );

      // Store file metadata in memory for listing
      const userFiles = this.uploadedFiles.get(user.zkLoginAddress) || [];
      userFiles.push({
        cid: walrusCid,
        filename: uploadRequest.filename,
        fileSize: uploadRequest.fileSize,
        uploadTimestamp: Date.now(),
        uploader: user.zkLoginAddress,
        isOwner: true,
        isEncrypted: uploadRequest.enableEncryption,
        encryptionKeys: encryptionKeys ? {
          publicKey: encryptionKeys.encryptionId,
          secretKey: encryptionKeys.symmetricKey,
        } : undefined,
      });
      this.uploadedFiles.set(user.zkLoginAddress, userFiles);

      return {
        success: true,
        fileCid: walrusCid,
        transactionDigest,
        walrusCid,
        message: 'File uploaded successfully',
      };
    } catch (error) {
      this.logger.error('Failed to upload file', error);
      return {
        success: false,
        fileCid: '',
        transactionDigest: '',
        walrusCid: uploadRequest.walrusCid || '',
        message: `Failed to upload file: ${error.message}`,
      };
    }
  }

  /**
   * Check file access and return file information if authorized
   */
  async accessFile(
    token: string,
    accessRequest: FileAccessRequest
  ): Promise<FileAccessResponse> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          authorized: false,
          message: 'Authentication failed',
        };
      }

      // Check if user is authorized to access the file (existing authorization)
      const isAuthorized = await this.authService.isUserAuthorizedForFile(
        token,
        accessRequest.fileCid
      );

      // Check access control rules
      const accessControlResult = await this.accessControlService.validateAccess(
        token,
        {
          fileCid: accessRequest.fileCid,
          userAddress: user.zkLoginAddress,
          userEmail: user.email,
        }
      );

      // User must pass both existing authorization AND access control rules
      if (!isAuthorized || !accessControlResult.accessGranted) {
        const reason = !isAuthorized
          ? 'User not authorized for this file'
          : accessControlResult.message || 'Access control rules not met';

        return {
          success: true,
          authorized: false,
          message: `Access denied: ${reason}`,
        };
      }

      // Get file metadata from smart contract
      const fileMetadata = await this.suiService.getFileMetadata(accessRequest.fileCid);

      if (!fileMetadata) {
        return {
          success: false,
          authorized: true,
          message: 'File not found',
        };
      }

      this.logger.log(
        `File access granted: ${accessRequest.fileCid} for ${user.zkLoginAddress}`
      );

      return {
        success: true,
        authorized: true,
        fileMetadata: {
          filename: fileMetadata.filename,
          fileSize: fileMetadata.fileSize,
          uploadTimestamp: fileMetadata.uploadTimestamp,
          uploader: fileMetadata.uploader,
        },
        walrusCid: accessRequest.fileCid, // Assuming CID is the same as Walrus CID
        message: 'Access granted',
      };
    } catch (error) {
      this.logger.error('Failed to check file access', error);
      return {
        success: false,
        authorized: false,
        message: `Failed to check file access: ${error.message}`,
      };
    }
  }

  /**
   * Grant access to a file for another user
   */
  async grantFileAccess(
    token: string,
    fileCid: string,
    recipientAddress: string
  ): Promise<{ success: boolean; message: string; transactionDigest?: string }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      // Grant access through smart contract
      const transactionDigest = await this.suiService.grantFileAccess(
        user.zkLoginAddress,
        fileCid,
        recipientAddress
      );

      this.logger.log(
        `Access granted: ${fileCid} from ${user.zkLoginAddress} to ${recipientAddress}`
      );

      return {
        success: true,
        message: 'Access granted successfully',
        transactionDigest,
      };
    } catch (error) {
      this.logger.error('Failed to grant file access', error);
      return {
        success: false,
        message: `Failed to grant access: ${error.message}`,
      };
    }
  }

  /**
   * Revoke access to a file for a user
   */
  async revokeFileAccess(
    token: string,
    fileCid: string,
    addressToRemove: string
  ): Promise<{ success: boolean; message: string; transactionDigest?: string }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      // Revoke access through smart contract
      const transactionDigest = await this.suiService.revokeFileAccess(
        user.zkLoginAddress,
        fileCid,
        addressToRemove
      );

      this.logger.log(
        `Access revoked: ${fileCid} by ${user.zkLoginAddress} for ${addressToRemove}`
      );

      return {
        success: true,
        message: 'Access revoked successfully',
        transactionDigest,
      };
    } catch (error) {
      this.logger.error('Failed to revoke file access', error);
      return {
        success: false,
        message: `Failed to revoke access: ${error.message}`,
      };
    }
  }

  /**
   * Download a file from Walrus storage
   */
  async downloadFile(
    token: string,
    fileCid: string
  ): Promise<{
    success: boolean;
    fileData?: Buffer;
    filename?: string;
    contentType?: string;
    message: string;
    isEncrypted?: boolean;
  }> {
    try {
      // Verify user authentication and access
      const accessResult = await this.accessFile(token, { fileCid });

      if (!accessResult.success || !accessResult.authorized) {
        return {
          success: false,
          message: accessResult.message,
        };
      }

      // Download file from Walrus
      const downloadResult = await this.walrusService.downloadFile(fileCid);

      if (!downloadResult.success) {
        return {
          success: false,
          message: `Failed to download from Walrus: ${downloadResult.error}`,
        };
      }

      // Check if file is encrypted by checking if it's a Mysten SEAL encrypted object
      let fileData = Buffer.from(downloadResult.data!);
      let isEncrypted = false;

      try {
        // Mysten SEAL encrypted objects are binary data, not JSON
        // We can detect them by trying to parse with the SEAL library
        // For now, we'll use a simple heuristic: if it's not valid UTF-8 text
        // and doesn't look like a common file format, assume it's encrypted
        const dataStr = new TextDecoder('utf-8', { fatal: true }).decode(downloadResult.data!);

        // If we can decode it as UTF-8 and it looks like JSON with old format, it's old encryption
        try {
          const metadata = JSON.parse(dataStr);
          if (metadata.chunks && metadata.scheme === 'BFV') {
            // This is old Microsoft SEAL format - not supported anymore
            this.logger.warn(`Detected old Microsoft SEAL encrypted file: ${fileCid} - not supported`);
          }
        } catch {
          // Not JSON, probably regular text file
        }
      } catch (error) {
        // Failed to decode as UTF-8, likely binary data (could be encrypted or regular binary file)
        // For Mysten SEAL, we'll assume binary data that's not a known format is encrypted
        isEncrypted = true;
        this.logger.log(`Detected potential Mysten SEAL encrypted file: ${fileCid}`);
      }

      this.logger.log(`File downloaded successfully: ${fileCid}${isEncrypted ? ' (encrypted)' : ''}`);

      return {
        success: true,
        fileData,
        filename: accessResult.fileMetadata?.filename,
        contentType: 'application/octet-stream',
        message: 'File downloaded successfully',
        isEncrypted, // Add this field to indicate if file is encrypted
      };
    } catch (error) {
      this.logger.error(`Failed to download file ${fileCid}:`, error);
      return {
        success: false,
        message: `Failed to download file: ${error.message}`,
      };
    }
  }

  /**
   * Download and decrypt an encrypted file using Mysten SEAL
   */
  async downloadAndDecryptFile(
    token: string,
    fileCid: string,
    sessionKey: any, // SessionKey from @mysten/seal
    txBytes: Uint8Array
  ): Promise<{
    success: boolean;
    fileData?: Buffer;
    filename?: string;
    contentType?: string;
    message: string;
  }> {
    try {
      // First download the encrypted file
      const downloadResult = await this.downloadFile(token, fileCid);

      if (!downloadResult.success) {
        return downloadResult;
      }

      // Check if file is actually encrypted
      if (!downloadResult.isEncrypted) {
        return {
          success: false,
          message: 'File is not encrypted',
        };
      }

      this.logger.log(`Decrypting file with Mysten SEAL: ${fileCid}`);

      // Decrypt the file using Mysten SEAL
      const decryptionResult = await this.sealService.decryptFile(
        new Uint8Array(downloadResult.fileData!),
        sessionKey,
        txBytes
      );

      if (!decryptionResult.success) {
        return {
          success: false,
          message: `Failed to decrypt file: ${decryptionResult.error}`,
        };
      }

      this.logger.log(`File decrypted successfully: ${fileCid}`);

      return {
        success: true,
        fileData: Buffer.from(decryptionResult.decryptedData!),
        filename: downloadResult.filename,
        contentType: downloadResult.contentType,
        message: 'File downloaded and decrypted successfully',
      };
    } catch (error) {
      this.logger.error(`Failed to download and decrypt file ${fileCid}:`, error);
      return {
        success: false,
        message: `Failed to download and decrypt file: ${error.message}`,
      };
    }
  }

  /**
   * Download and decrypt an encrypted file (Legacy method)
   * Note: This method is deprecated for Mysten SEAL.
   * Use downloadAndDecryptFile with proper session keys and transaction bytes.
   */
  async downloadEncryptedFile(
    token: string,
    fileCid: string,
    symmetricKey: string
  ): Promise<{
    success: boolean;
    fileData?: Buffer;
    filename?: string;
    contentType?: string;
    message: string;
  }> {
    this.logger.warn('downloadEncryptedFile is deprecated for Mysten SEAL. Use downloadAndDecryptFile instead.');

    return {
      success: false,
      message: 'This method is deprecated for Mysten SEAL. Use downloadAndDecryptFile with SessionKey and transaction bytes.',
    };
  }

  /**
   * Upload a file without authentication (for testing)
   */
  async uploadFileNoAuth(
    uploadRequest: FileUploadRequest
  ): Promise<FileUploadResponse> {
    try {
      this.logger.log(`Uploading file without auth: ${uploadRequest.filename}`);

      let walrusCid = uploadRequest.walrusCid;
      let dataToUpload = uploadRequest.fileData;

      // Handle encryption if requested
      if (uploadRequest.enableEncryption) {
        this.logger.log(`Encrypting file with SEAL: ${uploadRequest.filename}`);

        // Get package ID from environment or use default
        const packageId = process.env.SUI_PACKAGE_ID || '0x1'; // You'll need to set this

        const encryptionResult = await this.sealService.encryptFile(
          uploadRequest.fileData,
          {
            packageId,
            identity: uploadRequest.filename, // Use filename as identity
            threshold: 3, // Default threshold
          }
        );

        if (!encryptionResult.success) {
          return {
            success: false,
            fileCid: '',
            transactionDigest: '',
            walrusCid: '',
            message: `Failed to encrypt file: ${encryptionResult.error}`,
          };
        }

        dataToUpload = Buffer.from(encryptionResult.encryptedData!);
        this.logger.log(`File encrypted successfully: ${uploadRequest.filename}`);
      }

      // If no Walrus CID provided, upload to Walrus first
      if (!walrusCid) {
        this.logger.log(`Uploading file to Walrus: ${uploadRequest.filename}${uploadRequest.enableEncryption ? ' (encrypted)' : ''}`);

        // For no-auth uploads, always use regular upload (no zkLogin)
        const walrusResult = await this.walrusService.uploadFile(
          dataToUpload,
          uploadRequest.filename,
          uploadRequest.contentType
        );

        if (!walrusResult.success) {
          return {
            success: false,
            fileCid: '',
            transactionDigest: '',
            walrusCid: '',
            message: `Failed to upload to Walrus: ${walrusResult.error}`,
          };
        }

        walrusCid = walrusResult.blobId!;
        this.logger.log(`File uploaded to Walrus with CID: ${walrusCid}`);
      }

      // For testing, skip smart contract upload and return success
      const mockTransactionDigest = `mock_tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      this.logger.log(
        `File upload completed (no-auth mode): ${uploadRequest.filename} -> ${walrusCid}`
      );

      // Store file metadata in test mode storage
      this.testModeFiles.push({
        cid: walrusCid,
        filename: uploadRequest.filename,
        fileSize: uploadRequest.fileSize,
        uploadTimestamp: Date.now(),
        uploader: 'test-user',
        isOwner: true,
        isEncrypted: uploadRequest.enableEncryption,
        encryptionKeys: undefined, // Test mode doesn't store encryption keys
      });

      return {
        success: true,
        fileCid: walrusCid,
        transactionDigest: mockTransactionDigest,
        walrusCid,
        message: 'File uploaded successfully (no-auth mode)',
      };
    } catch (error) {
      this.logger.error('Failed to upload file (no-auth)', error);
      return {
        success: false,
        fileCid: '',
        transactionDigest: '',
        walrusCid: uploadRequest.walrusCid || '',
        message: `Failed to upload file: ${error.message}`,
      };
    }
  }

  /**
   * Download a file without authentication (for testing)
   */
  async downloadFileNoAuth(
    fileCid: string
  ): Promise<{
    success: boolean;
    fileData?: Buffer;
    filename?: string;
    contentType?: string;
    message: string;
  }> {
    try {
      this.logger.log(`Downloading file without auth: ${fileCid}`);

      // Download file from Walrus
      const downloadResult = await this.walrusService.downloadFile(fileCid);

      if (!downloadResult.success) {
        return {
          success: false,
          message: `Failed to download from Walrus: ${downloadResult.error}`,
        };
      }

      this.logger.log(`File downloaded successfully: ${fileCid}`);

      return {
        success: true,
        fileData: Buffer.from(downloadResult.data!),
        filename: `file_${fileCid.substring(0, 8)}.bin`, // Generate a filename
        contentType: 'application/octet-stream',
        message: 'File downloaded successfully',
      };
    } catch (error) {
      this.logger.error(`Failed to download file ${fileCid}:`, error);
      return {
        success: false,
        message: `Failed to download file: ${error.message}`,
      };
    }
  }

  /**
   * List files accessible by the authenticated user
   */
  async listUserFiles(token: string): Promise<{
    success: boolean;
    files: Array<{
      cid: string;
      filename: string;
      fileSize: number;
      uploadTimestamp: number;
      uploader: string;
      isOwner: boolean;
    }>;
    message: string;
  }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          files: [],
          message: 'Authentication failed',
        };
      }

      this.logger.log(`Listing files for user ${user.zkLoginAddress}`);

      // Get files from in-memory storage
      const userFiles = this.uploadedFiles.get(user.zkLoginAddress) || [];

      return {
        success: true,
        files: userFiles,
        message: userFiles.length > 0 ? `Found ${userFiles.length} files` : 'No files uploaded yet',
      };
    } catch (error) {
      this.logger.error('Failed to list user files', error);
      return {
        success: false,
        files: [],
        message: `Failed to list files: ${error.message}`,
      };
    }
  }

  /**
   * List files without authentication (for testing)
   */
  async listUserFilesNoAuth(): Promise<{
    success: boolean;
    files: Array<{
      cid: string;
      filename: string;
      fileSize: number;
      uploadTimestamp: number;
      uploader: string;
      isOwner: boolean;
    }>;
    message: string;
  }> {
    try {
      this.logger.log('Listing files (no auth - test mode)');

      return {
        success: true,
        files: this.testModeFiles,
        message: this.testModeFiles.length > 0 ? `Found ${this.testModeFiles.length} files` : 'No files uploaded yet',
      };
    } catch (error) {
      this.logger.error('Failed to list user files (no auth)', error);
      return {
        success: false,
        files: [],
        message: `Failed to list files: ${error.message}`,
      };
    }
  }

  /**
   * Clear all user files (authenticated)
   */
  async clearUserFiles(token: string): Promise<{
    success: boolean;
    message: string;
  }> {
    try {
      // Verify user authentication
      const user = await this.authService.verifyToken(token);
      if (!user) {
        return {
          success: false,
          message: 'Authentication failed',
        };
      }

      this.logger.log(`Clearing files for user ${user.zkLoginAddress}`);

      // Clear user files from memory
      const userFiles = this.uploadedFiles.get(user.zkLoginAddress) || [];
      const fileCount = userFiles.length;
      this.uploadedFiles.delete(user.zkLoginAddress);

      return {
        success: true,
        message: `Cleared ${fileCount} files for user`,
      };
    } catch (error) {
      this.logger.error('Failed to clear user files', error);
      return {
        success: false,
        message: `Failed to clear files: ${error.message}`,
      };
    }
  }

  /**
   * Clear all user files without authentication (for testing)
   */
  async clearUserFilesNoAuth(): Promise<{
    success: boolean;
    message: string;
  }> {
    try {
      this.logger.log('Clearing files (no auth - test mode)');

      // Clear test mode files
      const fileCount = this.testModeFiles.length;
      this.testModeFiles = [];

      return {
        success: true,
        message: `Cleared ${fileCount} files from test mode`,
      };
    } catch (error) {
      this.logger.error('Failed to clear user files (no auth)', error);
      return {
        success: false,
        message: `Failed to clear files: ${error.message}`,
      };
    }
  }

  /**
   * Download a file via share link
   */
  async downloadSharedFile(
    shareId: string,
    token?: string
  ): Promise<{
    success: boolean;
    fileData?: Buffer;
    filename?: string;
    contentType?: string;
    message: string;
    isEncrypted?: boolean;
  }> {
    try {
      this.logger.log(`Downloading shared file: ${shareId}`);

      // First, validate the share link
      const shareValidation = await this.accessControlService.validateShareLink(shareId, token);

      if (!shareValidation.success) {
        return {
          success: false,
          message: shareValidation.message,
        };
      }

      const fileCid = shareValidation.data?.fileCid;
      if (!fileCid) {
        return {
          success: false,
          message: 'File not found in share link',
        };
      }

      // Download the file from Walrus
      const downloadResult = await this.walrusService.downloadFile(fileCid);

      if (!downloadResult.success) {
        return {
          success: false,
          message: `Failed to download from Walrus: ${downloadResult.error}`,
        };
      }

      if (!downloadResult.data) {
        return {
          success: false,
          message: 'No file data received from Walrus',
        };
      }

      let fileData = Buffer.from(downloadResult.data);
      let isEncrypted = false;

      // Check if file is encrypted by trying to decode as UTF-8
      try {
        const dataStr = new TextDecoder('utf-8', { fatal: true }).decode(downloadResult.data);

        // If we can decode it as UTF-8 and it looks like JSON with old format, it's old encryption
        try {
          const metadata = JSON.parse(dataStr);
          if (metadata.chunks && metadata.scheme === 'BFV') {
            // This is old Microsoft SEAL format - not supported anymore
            this.logger.warn(`Detected old Microsoft SEAL encrypted file: ${fileCid} - not supported`);
            isEncrypted = true;
          }
        } catch {
          // Not JSON, probably regular text file
        }
      } catch (error) {
        // Failed to decode as UTF-8, likely binary data (could be encrypted or regular binary file)
        // For Mysten SEAL, we'll assume binary data that's not a known format is encrypted
        isEncrypted = true;
        this.logger.log(`Detected potential Mysten SEAL encrypted file: ${fileCid}`);
      }

      // Try to get file metadata from in-memory storage for better filename
      let filename = shareValidation.data?.filename || `shared-file-${fileCid.substring(0, 8)}`;
      let foundInMemory = false;

      this.logger.log(`Looking up file metadata for fileCid: ${fileCid}`);
      this.logger.log(`Initial filename from shareValidation: ${shareValidation.data?.filename || 'none'}`);

      // Try in-memory storage for file metadata
      {
        // Check all user files in memory
        this.logger.log(`Checking ${this.uploadedFiles.size} user file collections in memory`);
        for (const [userAddress, userFiles] of this.uploadedFiles.entries()) {
          this.logger.log(`Checking user ${userAddress} with ${userFiles.length} files`);
          const foundFile = userFiles.find(file => file.cid === fileCid);
          if (foundFile) {
            // Remove .encrypted suffix if present to show original filename
            filename = foundFile.filename.replace(/\.encrypted$/, '');
            isEncrypted = foundFile.isEncrypted || isEncrypted;
            foundInMemory = true;
            this.logger.log(`✅ Found file in user storage: ${foundFile.filename} -> ${filename} (encrypted: ${isEncrypted})`);
            break;
          }
        }

        // Also check test mode files
        this.logger.log(`Checking ${this.testModeFiles.length} test mode files`);
        const testFile = this.testModeFiles.find(file => file.cid === fileCid);
        if (testFile && !foundInMemory) {
          // Remove .encrypted suffix if present to show original filename
          filename = testFile.filename.replace(/\.encrypted$/, '');
          isEncrypted = testFile.isEncrypted || isEncrypted;
          foundInMemory = true;
          this.logger.log(`✅ Found file in test storage: ${testFile.filename} -> ${filename} (encrypted: ${isEncrypted})`);
        }

        if (!foundInMemory) {
          this.logger.warn(`❌ File not found in memory storage for CID: ${fileCid}`);
          this.logger.log(`Available user files:`, Array.from(this.uploadedFiles.entries()).map(([user, files]) =>
            ({ user, files: files.map(f => ({ cid: f.cid, filename: f.filename })) })
          ));
          this.logger.log(`Available test files:`, this.testModeFiles.map(f => ({ cid: f.cid, filename: f.filename })));
        }
      }

      const contentType = shareValidation.data?.contentType || 'application/octet-stream';

      // If file is encrypted, try to provide a better message and attempt decryption
      let message = 'File downloaded successfully';
      if (isEncrypted) {
        // For now, we can't automatically decrypt Mysten SEAL files without session keys
        // But we can provide helpful information
        message = 'Encrypted file downloaded - this file was encrypted during upload and may require the file owner to provide decryption access';
        this.logger.warn(`Downloaded encrypted file: ${filename} - automatic decryption not available for shared files`);

        // TODO: In the future, implement a mechanism where file owners can provide
        // decryption access for shared files, possibly through:
        // 1. Storing decryption keys with access control
        // 2. Using proxy re-encryption
        // 3. Having the owner decrypt and re-share
      }

      this.logger.log(`Shared file downloaded successfully: ${shareId} -> ${filename}${isEncrypted ? ' (encrypted)' : ''}`);

      return {
        success: true,
        fileData,
        filename,
        contentType,
        message,
        isEncrypted,
      };
    } catch (error) {
      this.logger.error(`Failed to download shared file ${shareId}:`, error);
      return {
        success: false,
        message: `Failed to download shared file: ${error.message}`,
      };
    }
  }
}
