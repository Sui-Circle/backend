import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { SuiService } from '../sui/sui.service';
import { AuthService } from '../auth/auth.service';
import { WalrusService } from '../storage/walrus/walrus.service';
import { SealService } from '../storage/seal/seal.service';
import { AccessControlService } from '../access-control/access-control.service';
import { WalletValidationService } from '../validation/wallet-validation.service';
import { TextDecoder } from 'util';

export interface FileUploadRequest {
  filename: string;
  fileSize: number;
  contentType: string;
  fileData: Buffer; // Raw file data to upload to Walrus
  walrusCid?: string; // Optional  will be generated if not provided
  enableEncryption?: boolean; // Whether to encrypt the file with SEAL
  walrusOptions?: {
    epochs?: number; // number of epochs to store; if omitted, store for max by default
    deletable?: boolean; // if omitted, default false (nondeletable)
  };
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

  // Inmemory storage for uploaded files (for testing)
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

  // Persistence to survive restarts
  private readonly dataDir = path.resolve(process.cwd(), 'data');
  private readonly persistenceFile = path.join(this.dataDir, 'uploads.json');

  // Inmemory storage for test mode files
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

  // Load persisted uploads from disk on first use
  private ensureLoadedFromDisk(): void {
    try {
      if (this.uploadedFiles.size > 0) return;
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      if (fs.existsSync(this.persistenceFile)) {
        const raw = fs.readFileSync(this.persistenceFile, 'utf8');
        if (raw) {
          const parsed: Record<string, any[]> = JSON.parse(raw);
          Object.entries(parsed).forEach(([address, files]) => {
            this.uploadedFiles.set(address, files as any[]);
          });
          this.logger.log(`Loaded persisted uploads for ${this.uploadedFiles.size} user(s)`);
        }
      }
    } catch (error) {
      this.logger.error('Failed to load persisted uploads:', error as any);
    }
  }

  private persistToDisk(): void {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      const asObject: Record<string, any[]> = {};
      for (const [address, files] of this.uploadedFiles.entries()) {
        asObject[address] = files;
      }
      fs.writeFileSync(this.persistenceFile, JSON.stringify(asObject, null, 2), 'utf8');
    } catch (error) {
      this.logger.error('Failed to persist uploads to disk:', error as any);
    }
  }

  /**
   * Upload a file with wallet authentication
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

      // Get user address (either wallet or zkLogin)
      const isWalletAuth = 'walletAddress' in user;
      const userAddress = isWalletAuth ? user.walletAddress : user.zkLoginAddress;
      if (!userAddress) {
        return {
          success: false,
          fileCid: '',
          transactionDigest: '',
          walrusCid: uploadRequest.walrusCid || '',
          message: 'No valid wallet address found',
        };
      }
      
      // Check for admin address usage
      const adminValidation = this.walletValidationService.validateNoAdminAddressUsage(
        userAddress,
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

        let walrusResult: import('../storage/walrus/walrus.service').WalrusUploadResult;

        // If zkLogin user and has parameters, use zkLogin upload; otherwise use regular upload
        if (!isWalletAuth && 'zkLoginAddress' in user && user.ephemeralKeyPair && user.jwt && user.userSalt) {
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
            uploadRequest.contentType,
            {
              epochs: uploadRequest.walrusOptions?.epochs,
              deletable: uploadRequest.walrusOptions?.deletable ?? false,
            }
          );
        } else {
          this.logger.log('➡️ Using regular Walrus upload');
          walrusResult = await this.walrusService.uploadFile(
            dataToUpload,
            uploadRequest.filename,
            uploadRequest.contentType,
            {
              epochs: uploadRequest.walrusOptions?.epochs,
              deletable: uploadRequest.walrusOptions?.deletable ?? false,
            }
          );
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

      // Check if we're using wallet authentication or zkLogin
      // (userAddress already computed above)
      
      this.logger.log('Authentication type:', {
        isWalletAuth,
        userAddress,
      });
      
      if (isWalletAuth) {
        // For wallet authentication, user will sign transaction directly with their wallet
        // We'll use the walletAddress for the upload
        this.logger.log(`Using wallet authentication for file upload: ${userAddress}`);
        
        // Call the SUI service with wallet address
        const transactionDigest = await this.suiService.uploadFileWithWallet(
          userAddress,
          walrusCid,
          uploadRequest.filename,
          uploadRequest.fileSize
        );

        // Store file metadata in memory for listing (walletauth path)
        const userFiles = this.uploadedFiles.get(userAddress) || [];
        userFiles.push({
          cid: walrusCid,
          filename: uploadRequest.filename,
          fileSize: uploadRequest.fileSize,
          uploadTimestamp: Date.now(),
          uploader: userAddress,
          isOwner: true,
          isEncrypted: uploadRequest.enableEncryption,
          encryptionKeys: encryptionKeys
            ? {
                publicKey: encryptionKeys.encryptionId,
                secretKey: encryptionKeys.symmetricKey,
              }
            : undefined,
        });
        this.uploadedFiles.set(userAddress, userFiles);
        this.persistToDisk();

        return {
          success: true,
          fileCid: walrusCid,
          transactionDigest,
          walrusCid,
          message: 'File uploaded successfully',
        };
      }
      
      // For zkLogin authentication
      const hasRequiredParams = user.ephemeralKeyPair && user.jwt && user.userSalt;

      this.logger.log('zkLogin parameter check:', {
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
        `File metadata uploaded to smart contract: ${uploadRequest.filename} by ${userAddress}`
      );

      // Store file metadata in memory for listing
      const userFiles = this.uploadedFiles.get(userAddress) || [];
      userFiles.push({
        cid: walrusCid,
        filename: uploadRequest.filename,
        fileSize: uploadRequest.fileSize,
        uploadTimestamp: Date.now(),
        uploader: userAddress,
        isOwner: true,
        isEncrypted: uploadRequest.enableEncryption,
        encryptionKeys: encryptionKeys ? {
          publicKey: encryptionKeys.encryptionId,
          secretKey: encryptionKeys.symmetricKey,
        } : undefined,
      });
      this.uploadedFiles.set(userAddress, userFiles);
      this.persistToDisk();

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
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      const userEmail = 'zkLoginAddress' in user ? (user.email || '') : undefined;
      const accessControlResult = await this.accessControlService.validateAccess(
        token,
        {
          fileCid: accessRequest.fileCid,
          userAddress,
          userEmail,
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

      this.logger.log(`File access granted: ${accessRequest.fileCid}`);

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

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;

      // Grant access through smart contract
      const transactionDigest = await this.suiService.grantFileAccess(
        userAddress,
        fileCid,
        recipientAddress
      );

      this.logger.log(`Access granted: ${fileCid} to ${recipientAddress}`);

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

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;

      // Revoke access through smart contract
      const transactionDigest = await this.suiService.revokeFileAccess(
        userAddress,
        fileCid,
        addressToRemove
      );

      this.logger.log(`Access revoked: ${fileCid} for ${addressToRemove}`);

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
    encryptionId?: string;
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

      // Prepare variables for return and detection
      let isEncrypted = false;
      const fileData = Buffer.from(downloadResult.data || new Uint8Array());

      // Check if file is encrypted by trying to decode as UTF8
      try {
        const dataStr = new TextDecoder('utf8', { fatal: true }).decode(fileData);

        // If we can decode it as UTF8 and it looks like JSON with old format, it's old encryption
        try {
          const metadata = JSON.parse(dataStr);
          if (metadata.chunks && metadata.scheme === 'BFV') {
            // This is old Microsoft SEAL format  not supported anymore
            this.logger.warn(`Detected old Microsoft SEAL encrypted file: ${fileCid}  not supported`);
            isEncrypted = true;
          }
        } catch {
          // Not JSON, probably regular text file
        }
      } catch (error) {
        // Failed to decode as UTF8, likely binary data (could be encrypted or regular binary file)
        // For Mysten SEAL, we'll assume binary data that's not a known format is encrypted
        isEncrypted = true;
        this.logger.log(`Detected potential Mysten SEAL encrypted file: ${fileCid}`);
      }

      this.logger.log(`File downloaded successfully: ${fileCid}${isEncrypted ? ' (encrypted)' : ''}`);

      // Try to retrieve encryptionId from stored metadata if encrypted
      let encryptionId: string | undefined = undefined;
      if (isEncrypted) {
        const stored = await this.getStoredFileMetadata(fileCid);
        const pubKey = stored?.encryptionKeys?.publicKey;
        if (pubKey) {
          encryptionId = pubKey;
          this.logger.log(`Found encryptionId for ${fileCid}: ${encryptionId}`);
        } else {
          this.logger.warn(`No encryptionId found in stored metadata for ${fileCid}`);
        }
      }

      return {
        success: true,
        fileData,
        filename: accessResult.fileMetadata?.filename,
        contentType: 'application/octet-stream',
        message: 'File downloaded successfully',
        isEncrypted, // Add this field to indicate if file is encrypted
        encryptionId,
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
   * Download and decrypt a Mysten SEAL encrypted file
   * This method handles the complete flow for backend-encrypted files
   */
  async downloadAndDecryptSeal(
    token: string,
    fileCid: string
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

      // Prepare cleaned filename without .encrypted suffix for any outputs
      const cleanedFilename = downloadResult.filename
        ? downloadResult.filename.replace(/\.encrypted$/, '')
        : undefined;

      // Check if file is actually encrypted
      if (!downloadResult.isEncrypted) {
        // File is not encrypted, return as-is (but clean filename if it had .encrypted suffix)
        return {
          success: true,
          fileData: downloadResult.fileData,
          filename: cleanedFilename,
          contentType: downloadResult.contentType,
          message: 'File downloaded (not encrypted)',
        };
      }

      // Get stored encryption metadata for this file
      const fileMetadata = await this.getStoredFileMetadata(fileCid);
      if (!fileMetadata?.encryptionKeys) {
        return {
          success: false,
          message: 'No encryption metadata found for this file',
        };
      }

      this.logger.log(`Attempting to decrypt Mysten SEAL file: ${fileCid}`);

      // For Mysten SEAL files encrypted by our backend, we need to use a different approach
      // Since the backend encrypted the file, it should be able to decrypt it using the stored metadata
      
      // Try to parse the encrypted data to see if it contains SEAL metadata
      try {
        const encryptedData = new Uint8Array(downloadResult.fileData!);
        
        // Create a minimal session key and tx bytes for SEAL decryption
        // In a real production system, these would be properly managed
        const mockSessionKey = { 
          // This is a simplified approach - in production you'd need proper session management
          data: new Uint8Array(32) // Mock 32-byte key
        };
        const mockTxBytes = new Uint8Array(64); // Mock transaction bytes

        // Attempt decryption with SEAL service
        const decryptionResult = await this.sealService.decryptFile(
          encryptedData,
          mockSessionKey as any,
          mockTxBytes
        );

        if (decryptionResult.success) {
          this.logger.log(`File decrypted successfully with SEAL: ${fileCid}`);
          return {
            success: true,
            fileData: Buffer.from(decryptionResult.decryptedData!),
            filename: cleanedFilename,
            contentType: downloadResult.contentType,
            message: 'File downloaded and decrypted successfully',
          };
        } else {
          // SEAL decryption failed, check if it's client-side encrypted data
          this.logger.warn(`SEAL decryption failed: ${decryptionResult.error}`);
        }
      } catch (sealError) {
        this.logger.warn(`SEAL decryption error: ${sealError.message}`);
      }

      // Try to parse as client-side encrypted JSON (fallback for mock encryption)
      try {
        const dataStr = new TextDecoder().decode(downloadResult.fileData!);
        const metadata = JSON.parse(dataStr);
        
        if (metadata.algorithm === 'Seal-BFV' && metadata.encryptedChunks) {
          // This is client-side mock encrypted data
          this.logger.log(`Decrypting client-side mock encrypted file: ${fileCid}`);
          const originalData = new Uint8Array(metadata.encryptedChunks[0]);
          
          return {
            success: true,
            fileData: Buffer.from(originalData),
            filename: cleanedFilename,
            contentType: downloadResult.contentType,
            message: 'File downloaded and decrypted (mock encryption)',
          };
        }
      } catch (parseError) {
        // Not JSON, continue to other methods
      }

      return {
        success: false,
        message: 'Unable to decrypt file - unknown encryption format',
      };
    } catch (error) {
      this.logger.error(`Failed to download and decrypt SEAL file ${fileCid}:`, error);
      return {
        success: false,
        message: `Failed to download and decrypt file: ${error.message}`,
      };
    }
  }

  /**
   * Get stored file metadata for a given CID
   */
  private async getStoredFileMetadata(fileCid: string): Promise<any> {
    // Check in-memory storage first
    for (const [userAddress, files] of this.uploadedFiles.entries()) {
      const file = files.find(f => f.cid === fileCid);
      if (file) {
        return file;
      }
    }

    // Check test mode files
    const testFile = this.testModeFiles.find(f => f.cid === fileCid);
    if (testFile) {
      return testFile;
    }

    return null;
  }

  /**
   * Download and decrypt an encrypted file (Legacy method)
   * Note: This method is deprecated for Mysten SEAL.
   * Use downloadAndDecryptSeal for backend-encrypted files.
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
    this.logger.warn('downloadEncryptedFile is deprecated for Mysten SEAL. Use downloadAndDecryptSeal instead.');

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

        // For noauth uploads, always use regular upload (no zkLogin)
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
        `File upload completed (noauth mode): ${uploadRequest.filename} > ${walrusCid}`
      );

      // Store file metadata in test mode storage
      this.testModeFiles.push({
        cid: walrusCid,
        filename: uploadRequest.filename,
        fileSize: uploadRequest.fileSize,
        uploadTimestamp: Date.now(),
        uploader: 'testuser',
        isOwner: true,
        isEncrypted: uploadRequest.enableEncryption,
        encryptionKeys: undefined, // Test mode doesn't store encryption keys
      });

      return {
        success: true,
        fileCid: walrusCid,
        transactionDigest: mockTransactionDigest,
        walrusCid,
        message: 'File uploaded successfully (noauth mode)',
      };
    } catch (error) {
      this.logger.error('Failed to upload file (noauth)', error);
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
   isEncrypted?: boolean;
   encryptionId?: string;
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

      // Detect encryption similar to authenticated path
      let isEncrypted = false;
      try {
        const dataStr = new TextDecoder('utf8', { fatal: true }).decode(downloadResult.data!);
        try {
          const metadata = JSON.parse(dataStr);
          if (metadata.chunks && metadata.scheme === 'BFV') {
            this.logger.warn(`Detected old Microsoft SEAL encrypted file: ${fileCid}  not supported`);
            isEncrypted = true;
          }
        } catch {
          // Not JSON, probably regular text file
        }
      } catch {
        isEncrypted = true; // binary not utf8
        this.logger.log(`Detected potential Mysten SEAL encrypted file: ${fileCid}`);
      }

      this.logger.log(`File downloaded successfully: ${fileCid}${isEncrypted ? ' (encrypted)' : ''}`);

      // Try to retrieve encryptionId from stored metadata if encrypted
      let encryptionId: string | undefined = undefined;
      if (isEncrypted) {
        const stored = await this.getStoredFileMetadata(fileCid);
        const pubKey = stored?.encryptionKeys?.publicKey;
        if (pubKey) {
          encryptionId = pubKey;
          this.logger.log(`Found encryptionId for ${fileCid}: ${encryptionId}`);
        } else {
          this.logger.warn(`No encryptionId found in stored metadata for ${fileCid}`);
        }
      }

      return {
        success: true,
        fileData: Buffer.from(downloadResult.data!),
        filename: `file_${fileCid.substring(0, 8)}.bin`, // Generate a filename
        contentType: 'application/octet-stream',
        message: 'File downloaded successfully',
        isEncrypted,
        encryptionId,
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

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      this.logger.log(`Listing files for user ${userAddress}`);

      // Ensure inmemory cache loaded from disk
      this.ensureLoadedFromDisk();

      // Get user files from memory/disk cache
      const userFiles = this.uploadedFiles.get(userAddress) || [];

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
      this.logger.log('Listing files (no auth  test mode)');

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

      // Get user address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
      this.logger.log(`Clearing files for user ${userAddress}`);

      // Clear user files from memory
      const userFiles = this.uploadedFiles.get(userAddress) || [];
      const fileCount = userFiles.length;
      this.uploadedFiles.delete(userAddress);

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
      this.logger.log('Clearing files (no auth  test mode)');

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
    encryptionId?: string;
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

      // Check if file is encrypted by trying to decode as UTF8
      try {
        const dataStr = new TextDecoder('utf8', { fatal: true }).decode(downloadResult.data);

        // If we can decode it as UTF8 and it looks like JSON with old format, it's old encryption
        try {
          const metadata = JSON.parse(dataStr);
          if (metadata.chunks && metadata.scheme === 'BFV') {
            // This is old Microsoft SEAL format  not supported anymore
            this.logger.warn(`Detected old Microsoft SEAL encrypted file: ${fileCid}  not supported`);
            isEncrypted = true;
          }
        } catch {
          // Not JSON, probably regular text file
        }
      } catch (error) {
        // Failed to decode as UTF8, likely binary data (could be encrypted or regular binary file)
        // For Mysten SEAL, we'll assume binary data that's not a known format is encrypted
        isEncrypted = true;
        this.logger.log(`Detected potential Mysten SEAL encrypted file: ${fileCid}`);
      }

      // Try to get file metadata from inmemory storage for better filename
      let filename = shareValidation.data?.filename || `sharedfile${fileCid.substring(0, 8)}`;
      let foundInMemory = false;

      this.logger.log(`Looking up file metadata for fileCid: ${fileCid}`);
      this.logger.log(`Initial filename from shareValidation: ${shareValidation.data?.filename || 'none'}`);

      // Try inmemory storage for file metadata
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
            this.logger.log(`✅ Found file in user storage: ${foundFile.filename} > ${filename} (encrypted: ${isEncrypted})`);
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
          this.logger.log(`✅ Found file in test storage: ${testFile.filename} > ${filename} (encrypted: ${isEncrypted})`);
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
        message = 'Encrypted file downloaded  this file was encrypted during upload and may require the file owner to provide decryption access';
        this.logger.warn(`Downloaded encrypted file: ${filename}  automatic decryption not available for shared files`);

        // TODO: In the future, implement a mechanism where file owners can provide
        // decryption access for shared files, possibly through:
        // 1. Storing decryption keys with access control
        // 2. Using proxy reencryption
        // 3. Having the owner decrypt and reshare
      }

      this.logger.log(`Shared file downloaded successfully: ${shareId} > ${filename}${isEncrypted ? ' (encrypted)' : ''}`);

      // Try to retrieve encryptionId from stored metadata if encrypted
      let encryptionId: string | undefined = undefined;
      if (isEncrypted) {
        const stored = await this.getStoredFileMetadata(fileCid);
        const pubKey = stored?.encryptionKeys?.publicKey;
        if (pubKey) {
          encryptionId = pubKey;
          this.logger.log(`Found encryptionId for ${fileCid}: ${encryptionId}`);
        } else {
          this.logger.warn(`No encryptionId found in stored metadata for ${fileCid}`);
        }
      }

      return {
        success: true,
        fileData,
        filename,
        contentType,
        message,
        isEncrypted,
        encryptionId,
      };
    } catch (error) {
      this.logger.error('Failed to download shared file', error);
      return {
        success: false,
        message: `Failed to download shared file: ${error.message}`,
      };
    }
  }
}
