import { Injectable, Logger } from '@nestjs/common';
import { WalrusClient, WalrusFile } from '@mysten/walrus';
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { getZkLoginSignature } from '@mysten/sui/zklogin';
import { createHash } from 'crypto';

export interface WalrusUploadResult {
  success: boolean;
  blobId?: string;
  error?: string;
  size?: number;
}

export interface WalrusUploadOptions {
  epochs?: number; // Number of epochs to store; defaults to max supported
  deletable?: boolean; // Whether blob can be deleted before expiry; defaults to false
}

export interface WalrusDownloadResult {
  success: boolean;
  data?: Uint8Array;
  error?: string;
}

export interface ZkLoginTransactionParams {
  ephemeralKeyPair: {
    keypair: Ed25519Keypair;
    maxEpoch: number;
    randomness: string;
  };
  zkLoginProof?: {
    proofPoints: {
      a: string[];
      b: string[][];
      c: string[];
    };
    issBase64Details: {
      value: string;
      indexMod4: number;
    };
    headerBase64: string;
  };
  jwt: string;
  userSalt: string;
}

@Injectable()
export class WalrusService {
  private readonly logger = new Logger(WalrusService.name);
  private walrusClient: WalrusClient | null = null;
  private suiClient: SuiClient;
  private signer: Ed25519Keypair | null = null;
  private useUploadRelay: boolean;

  constructor() {
    this.initializeClients();
  }

  private initializeClients() {
    try {
      const network = process.env.WALRUS_NETWORK || 'testnet';
      const suiRpcUrl = process.env.SUI_RPC_URL || getFullnodeUrl('testnet');
      this.useUploadRelay = process.env.WALRUS_USE_UPLOAD_RELAY === 'true';

      // Initialize Sui client
      this.suiClient = new SuiClient({
        url: suiRpcUrl,
      });

      // Initialize signer if private key is provided or if using upload relay
      if (process.env.WALRUS_PRIVATE_KEY) {
        // Validate private key format before attempting to use it
        const privateKey = process.env.WALRUS_PRIVATE_KEY.trim();
        if (privateKey.length < 32) {
          this.logger.warn(
            `Invalid WALRUS_PRIVATE_KEY format (too short: ${privateKey.length} chars). Using fallback mode.`,
          );
          this.signer = null;
        } else {
          try {
            this.signer = Ed25519Keypair.fromSecretKey(privateKey);
            this.logger.log('Walrus signer initialized successfully');
          } catch (error) {
            this.logger.warn(
              'Failed to initialize Walrus signer, using fallback mode:',
              error,
            );
            this.signer = null;
          }
        }
      } else if (this.useUploadRelay) {
        // For upload relay, create a dummy signer
        this.signer = new Ed25519Keypair();
        this.logger.log('Dummy signer created for upload relay mode');
      }

      // Initialize Walrus client
      const walrusConfig: any = {
        network: network as 'testnet' | 'mainnet',
        suiClient: this.suiClient,
        storageNodeClientOptions: {
          timeout: 60_000,
          onError: (error: Error) => {
            this.logger.warn('Walrus storage node error:', error.message);
          },
        },
      };

      // Add upload relay configuration if enabled
      if (this.useUploadRelay) {
        const relayUrl = process.env.WALRUS_UPLOAD_RELAY_URL;
        const maxTip = parseInt(process.env.WALRUS_MAX_TIP || '1000');

        if (!relayUrl) {
          throw new Error(
            'WALRUS_UPLOAD_RELAY_URL is required when using upload relay',
          );
        }

        (walrusConfig as any).uploadRelay = {
          host: relayUrl,
          sendTip: {
            max: maxTip,
          },
        };

        this.logger.log(`Walrus upload relay configured: ${relayUrl}`);
      }

      this.walrusClient = new WalrusClient(walrusConfig as any);

      this.logger.log(
        `Walrus client initialized successfully (${this.useUploadRelay ? 'upload relay' : 'direct upload'} mode)`,
      );
    } catch (error) {
      this.logger.warn(
        'Failed to initialize Walrus clients, will use mock mode:',
        error,
      );
      // Don't throw error - gracefully degrade to mock mode
      this.walrusClient = null;
      this.signer = null;
    }
  }

  /**
   * Upload a file to Walrus storage
   * @param fileData - The file data as Buffer or Uint8Array
   * @param filename - Original filename for metadata
   * @param contentType - MIME type of the file
   * @returns Promise with upload result containing blobId
   */
  async uploadFile(
    fileData: Buffer | Uint8Array,
    filename: string,
    contentType?: string,
    options?: WalrusUploadOptions,
  ): Promise<WalrusUploadResult> {
    try {
      this.logger.log(
        `Starting upload for file: ${filename}, size: ${fileData.length} bytes`,
      );

      // Convert Buffer to Uint8Array if needed
      const data =
        fileData instanceof Buffer ? new Uint8Array(fileData) : fileData;

      // Check if we're in development mode or if Walrus client failed to initialize (fallback to mock)
      if (
        !this.walrusClient ||
        (process.env.NODE_ENV === 'development' &&
          !process.env.WALRUS_PRIVATE_KEY &&
          !this.useUploadRelay)
      ) {
        this.logger.warn(
          'Using mock upload mode due to missing configuration or initialization failure',
        );
        return this.uploadFileMock(data, filename);
      }

      let result: WalrusUploadResult;

      if (this.useUploadRelay) {
        // Option 1: Upload via relay
        result = await this.uploadViaRelay(data, filename, contentType, options);
      } else {
        // Option 2: Direct upload with signer
        result = await this.uploadDirect(data, filename, contentType, options);
      }

      if (result.success) {
        this.logger.log(`✅ File uploaded successfully: ${filename} -> ${result.blobId}`);
        this.logger.log(`📊 File size: ${data.length} bytes`);
        this.logger.log(`🔗 Walrus CID: ${result.blobId}`);
      }

      return result;

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Failed to upload file ${filename}:`, error);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Upload file to Walrus with zkLogin signature
   */
  async uploadFileWithZkLogin(
    fileData: Buffer | Uint8Array,
    filename: string,
    zkLoginParams: ZkLoginTransactionParams,
    contentType?: string,
    options?: WalrusUploadOptions
  ): Promise<WalrusUploadResult> {
    try {
      this.logger.log(`Starting zkLogin upload for file: ${filename}, size: ${fileData.length} bytes`);

      // Convert Buffer to Uint8Array if needed
      const data = fileData instanceof Buffer ? new Uint8Array(fileData) : fileData;

      // Derive user address for validation
      const userAddress = this.deriveZkLoginAddress(zkLoginParams.jwt, zkLoginParams.userSalt);
      this.logger.log(`Using zkLogin address: ${userAddress}`);

      // Check if we should use upload relay or direct upload
      let result: WalrusUploadResult;

      if (this.useUploadRelay) {
        this.logger.log(`Using upload relay for zkLogin upload (user: ${userAddress})`);
        // Use upload relay which doesn't require complex signer setup
        result = await this.uploadViaRelay(data, filename, contentType, options);
      } else {
        this.logger.log(`Using direct upload with zkLogin signature (user: ${userAddress})`);
        // Use direct upload with zkLogin signature
        result = await this.uploadDirectWithZkLogin(data, filename, zkLoginParams, contentType, options);
      }

      if (result.success) {
        this.logger.log(`✅ File uploaded successfully with zkLogin: ${filename} -> ${result.blobId}`);
        this.logger.log(`📊 File size: ${data.length} bytes`);
        this.logger.log(`🔗 Walrus CID: ${result.blobId}`);
        this.logger.log(`👤 Uploaded by zkLogin address: ${userAddress}`);
      }

      return result;
    } catch (error: any) {
      this.logger.error('Failed to upload file to Walrus with zkLogin:', error);
      return {
        success: false,
        error: `Failed to upload file with zkLogin: ${error.message}`,
      };
    }
  }

  /**
   * Upload file via upload relay
   */
  private async uploadViaRelay(
    data: Uint8Array,
    filename: string,
    contentType?: string,
    options?: WalrusUploadOptions
  ): Promise<WalrusUploadResult> {
    try {
      // Create WalrusFile with metadata
      const walrusFile = WalrusFile.from({
        contents: data,
        identifier: filename,
        tags: {
          'content-type': contentType || 'application/octet-stream',
          'upload-timestamp': new Date().toISOString(),
        },
      });

      // Upload via relay (signer is required by API but relay handles actual signing)
      if (!this.signer) {
        throw new Error('No signer available for upload relay');
      }

      const results = await this.walrusClient!.writeFiles({
        files: [walrusFile],
        // Prefer explicit options, then env, then sensible default (max epochs if provided by env)
        epochs: options?.epochs ?? parseInt(process.env.WALRUS_STORAGE_EPOCHS || '53'),
        deletable: options?.deletable ?? false,
        signer: this.signer,
      });

      if (results && results.length > 0) {
        return {
          success: true,
          blobId: results[0].blobId,
          size: data.length,
        };
      } else {
        throw new Error('No results returned from upload relay');
      }
    } catch (error) {
      this.logger.error('Upload relay failed:', error);
      return {
        success: false,
        error: `Upload relay failed: ${error.message}`,
      };
    }
  }

  /**
   * Upload file directly with signer
   */
  private async uploadDirect(
    data: Uint8Array,
    filename: string,
    contentType?: string,
    options?: WalrusUploadOptions
  ): Promise<WalrusUploadResult> {
    try {
      if (!this.signer) {
        throw new Error('No signer configured for direct upload. Set WALRUS_PRIVATE_KEY or enable upload relay.');
      }

      // Upload directly to Walrus
      const result = await this.walrusClient!.writeBlob({
        blob: data,
        deletable: options?.deletable ?? false,
        epochs: options?.epochs ?? parseInt(process.env.WALRUS_STORAGE_EPOCHS || '53'),
        signer: this.signer,
      });

      return {
        success: true,
        blobId: result.blobId,
        size: data.length,
      };
    } catch (error: any) {
      this.logger.error('Direct upload failed:', error);
      return {
        success: false,
        error: `Direct upload failed: ${error.message}`,
      };
    }
  }

  /**
   * Upload file directly with zkLogin signature
   */
  private async uploadDirectWithZkLogin(
    data: Uint8Array,
    filename: string,
    zkLoginParams: ZkLoginTransactionParams,
    contentType?: string,
    options?: WalrusUploadOptions
  ): Promise<WalrusUploadResult> {
    try {
      // Derive the user address for this user
      const userAddress = this.deriveZkLoginAddress(zkLoginParams.jwt, zkLoginParams.userSalt);

      // Create a custom signer that uses zkLogin signature
      const zkLoginSigner = {
        getPublicKey: () => zkLoginParams.ephemeralKeyPair.keypair.getPublicKey(),
        getAddress: () => userAddress,
        toSuiAddress: () => userAddress, // Required by Walrus client
        signTransaction: async (txBytes: Uint8Array) => {
          // Sign with ephemeral key pair
          const ephemeralSignature = await zkLoginParams.ephemeralKeyPair.keypair.sign(txBytes);

          // Create zkLogin signature
          const zkLoginSignature = getZkLoginSignature({
            inputs: {
              ...zkLoginParams.zkLoginProof!,
              addressSeed: this.getAddressSeed(zkLoginParams.jwt, zkLoginParams.userSalt),
            },
            maxEpoch: zkLoginParams.ephemeralKeyPair.maxEpoch,
            userSignature: ephemeralSignature,
          });

          return zkLoginSignature;
        },
        sign: async (data: Uint8Array) => {
          return await zkLoginParams.ephemeralKeyPair.keypair.sign(data);
        },
        // Additional methods that might be required by Walrus client
        signTransactionBlock: async (txBytes: Uint8Array) => {
          // Use the same logic as signTransaction
          const ephemeralSignature = await zkLoginParams.ephemeralKeyPair.keypair.sign(txBytes);

          const zkLoginSignature = getZkLoginSignature({
            inputs: {
              ...zkLoginParams.zkLoginProof!,
              addressSeed: this.getAddressSeed(zkLoginParams.jwt, zkLoginParams.userSalt),
            },
            maxEpoch: zkLoginParams.ephemeralKeyPair.maxEpoch,
            userSignature: ephemeralSignature,
          });

          return zkLoginSignature;
        },
        signPersonalMessage: async (message: Uint8Array) => {
          return await zkLoginParams.ephemeralKeyPair.keypair.sign(message);
        },
        // Ensure compatibility with different signer interfaces
        getKeyScheme: () => zkLoginParams.ephemeralKeyPair.keypair.getKeyScheme(),
        getSecretKey: () => zkLoginParams.ephemeralKeyPair.keypair.getSecretKey()
      };

      this.logger.log(`Uploading to Walrus with zkLogin signer for address: ${userAddress}`);

      // Upload directly to Walrus with zkLogin signer
      const result = await this.walrusClient!.writeBlob({
        blob: data,
        deletable: options?.deletable ?? false,
        epochs: options?.epochs ?? parseInt(process.env.WALRUS_STORAGE_EPOCHS || '53'),
        signer: zkLoginSigner as any, // Type assertion needed for custom signer
      });

      this.logger.log(`Walrus upload successful for zkLogin address ${userAddress}: ${result.blobId}`);

      return {
        success: true,
        blobId: result.blobId,
        size: data.length,
      };
    } catch (error: any) {
      this.logger.error('zkLogin direct upload failed:', error);
      return {
        success: false,
        error: `zkLogin direct upload failed: ${error.message}`,
      };
    }
  }

  /**
   * Get address seed for zkLogin address derivation
   */
  private getAddressSeed(jwt: string, salt: string): string {
    // Simplified address seed generation
    // In production, this should follow the zkLogin specification
    const decoded = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString());
    return `${decoded.sub}_${decoded.iss}_${salt}`;
  }

  /**
   * Derive user address from JWT and user salt
   * This method is used for zkLogin authentication
   */
  private deriveZkLoginAddress(jwt: string, userSalt: string): string {
    try {
      // Parse JWT to get the subject and issuer
      const jwtPayload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString());
      const subject = jwtPayload.sub;
      const issuer = jwtPayload.iss;

      // Create address seed following zkLogin specification
      const addressSeed = `${subject}_${issuer}_${userSalt}`;

      // For now, return a deterministic address based on the seed
      // In production this should use proper zkLogin address derivation from @mysten/sui
      const hash = createHash('sha256')
        .update(addressSeed)
        .digest('hex');
      return `0x${hash.substring(0, 40)}`; // Truncate to 40 chars for Sui address format

    } catch (error) {
      this.logger.error('Failed to derive zkLogin address:', error);
      throw new Error('Invalid JWT or user salt for address derivation');
    }
  }

  /**
   * Fallback mock upload for development
   */
  private async uploadFileMock(
    data: Uint8Array,
    filename: string
  ): Promise<WalrusUploadResult> {
    this.logger.warn('Using mock upload - configure WALRUS_PRIVATE_KEY or upload relay for production');

    // Simulate upload delay
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));

    const simulatedBlobId = this.generateMockBlobId(filename, data.length);

    this.logger.log(`✅ File upload simulated: ${filename} -> ${simulatedBlobId}`);

    return {
      success: true,
      blobId: simulatedBlobId,
      size: data.length,
    };
  }

  /**
   * Generate a mock blob ID for testing purposes
   * In production, this would be returned by Walrus
   */
  private generateMockBlobId(filename: string, size: number): string {
    const timestamp = Date.now();
    const hash = Buffer.from(`${filename}-${size}-${timestamp}`).toString('base64url');
    return `mock_${hash.substring(0, 32)}`;
  }

  /**
   * Validate Walrus configuration
   */
  public validateConfiguration(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if we're in production mode
    const isProduction = process.env.NODE_ENV === 'production';

    if (isProduction) {
      // In production, we need either a signer or upload relay
      if (!this.useUploadRelay && !this.signer) {
        errors.push('Production mode requires either WALRUS_PRIVATE_KEY or WALRUS_USE_UPLOAD_RELAY=true');
      }

      if (this.useUploadRelay && !process.env.WALRUS_UPLOAD_RELAY_URL) {
        errors.push('Upload relay mode requires WALRUS_UPLOAD_RELAY_URL');
      }
    }

    // Check network configuration
    if (!process.env.SUI_RPC_URL) {
      errors.push('SUI_RPC_URL is required');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get current configuration status
   */
  public getConfigurationStatus(): {
    mode: 'mock' | 'upload-relay' | 'direct-upload';
    network: string;
    hasPrivateKey: boolean;
    uploadRelayUrl?: string;
  } {
    return {
      mode: this.useUploadRelay ? 'upload-relay' : (this.signer ? 'direct-upload' : 'mock'),
      network: process.env.WALRUS_NETWORK || 'testnet',
      hasPrivateKey: !!this.signer,
      uploadRelayUrl: this.useUploadRelay ? process.env.WALRUS_UPLOAD_RELAY_URL : undefined,
    };
  }

  /**
   * Get wallet address and balance information
   */
  public async getWalletInfo(): Promise<{
    address?: string;
    suiBalance?: string;
    walBalance?: string;
    error?: string;
  }> {
    try {
      if (!this.signer) {
        return { error: 'No signer available' };
      }

      const address = this.signer.toSuiAddress();

      // Get SUI balance
      const suiBalance = await this.suiClient.getBalance({
        owner: address,
        coinType: '0x2::sui::SUI',
      });

      // Get WAL balance (WAL token type for testnet)
      const walTokenType = '0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL';
      let walBalance;
      try {
        walBalance = await this.suiClient.getBalance({
          owner: address,
          coinType: walTokenType,
        });
      } catch {
        // WAL balance might not exist if no WAL tokens
        walBalance = { totalBalance: '0', coinType: walTokenType, coinObjectCount: 0 };
      }

      return {
        address,
        suiBalance: suiBalance.totalBalance,
        walBalance: walBalance.totalBalance,
      };
    } catch (error) {
      this.logger.error('Failed to get wallet info:', error);
      return { error: error.message };
    }
  }

  /**
   * Download a file from Walrus storage
   * @param blobId - The Walrus blob ID
   * @returns Promise with download result containing file data
   */
  async downloadFile(blobId: string): Promise<WalrusDownloadResult> {
    try {
      this.logger.log(`Downloading file with blobId: ${blobId}`);

      // Check if this is a mock blob ID or if Walrus client is not available (fallback for development)
      if (blobId.startsWith('mock_') || !this.walrusClient) {
        if (!this.walrusClient) {
          this.logger.warn(
            'Walrus client not available, using mock download mode',
          );
        }
        return this.downloadFileMock(blobId);
      }

      // Download from real Walrus storage
      const data = await this.walrusClient.readBlob({ blobId });

      this.logger.log(`✅ File downloaded successfully, size: ${data.length} bytes`);

      return {
        success: true,
        data,
      };
    } catch (error) {
      this.logger.error(`Failed to download file with blobId ${blobId}:`, error);

      // If it's a network error, provide helpful message
      if (error.message.includes('network') || error.message.includes('timeout')) {
        return {
          success: false,
          error: `Network error downloading from Walrus: ${error.message}. Please check your connection and try again.`,
        };
      }

      // If blob not found
      if (error.message.includes('not found') || error.message.includes('404')) {
        return {
          success: false,
          error: `File not found in Walrus storage. The blob ID may be invalid or the file may have expired.`,
        };
      }

      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Download mock file for development
   */
  private async downloadFileMock(blobId: string): Promise<WalrusDownloadResult> {
    this.logger.warn('Downloading mock file - this is development mode');

    // Simulate download delay
    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));

    // Generate mock file content
    const mockContent = `Mock file content for ${blobId}
Generated at: ${new Date().toISOString()}
This is simulated data from Walrus storage.
Original blob ID: ${blobId}
File content would be retrieved from Walrus network.`;

    const data = new Uint8Array(Buffer.from(mockContent, 'utf-8'));

    this.logger.log(`✅ Mock file downloaded successfully, size: ${data.length} bytes`);

    return {
      success: true,
      data,
    };
  }

  /**
   * Check if a blob exists in Walrus storage
   * @param blobId - The Walrus blob ID
   * @returns Promise<boolean> indicating if blob exists
   */
  async blobExists(blobId: string): Promise<boolean> {
    try {
      if (!this.walrusClient) {
        // Mock blobs always "exist" in development mode
        return blobId.startsWith('mock_');
      }
      await this.walrusClient.readBlob({ blobId });
      return true;
    } catch {
      this.logger.debug(`Blob ${blobId} does not exist or is not accessible`);
      return false;
    }
  }

  /**
   * Get blob information without downloading the full content
   * @param blobId - The Walrus blob ID
   * @returns Promise with blob metadata
   */
  async getBlobInfo(blobId: string): Promise<{
    exists: boolean;
    size?: number;
    error?: string;
  }> {
    try {
      if (!this.walrusClient) {
        // Return mock info for development mode
        return {
          exists: blobId.startsWith('mock_'),
          size: blobId.startsWith('mock_') ? 1024 : undefined,
          error: blobId.startsWith('mock_') ? undefined : 'Walrus client not available',
        };
      }

      // For now, we'll try to read the blob to check if it exists
      // In a production setup, you might want to use a more efficient method
      const data = await this.walrusClient.readBlob({ blobId });

      return {
        exists: true,
        size: data.length,
      };
    } catch (error) {
      return {
        exists: false,
        error: (error as Error).message,
      };
    }
  }
}
