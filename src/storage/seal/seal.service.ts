import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SealClient, getAllowlistedKeyServers, type KeyServerConfig } from '@mysten/seal';
import { SuiClient } from '@mysten/sui/client';
import { SessionKey } from '@mysten/seal';

export interface EncryptionResult {
  success: boolean;
  encryptedData?: Uint8Array;
  symmetricKey?: Uint8Array;
  encryptionId?: string;
  error?: string;
}

export interface DecryptionResult {
  success: boolean;
  decryptedData?: Uint8Array;
  error?: string;
}

export interface SealEncryptionOptions {
  packageId: string;
  identity: string;
  threshold?: number;
  additionalData?: Uint8Array;
}

@Injectable()
export class SealService implements OnModuleInit {
  private readonly logger = new Logger(SealService.name);
  private sealClient: SealClient | null = null;
  private suiClient: SuiClient;
  private isInitialized = false;

  async onModuleInit() {
    await this.initializeSeal();
  }

  /**
   * Initialize the Mysten SEAL library
   */
  private async initializeSeal(): Promise<void> {
    try {
      this.logger.log('Initializing Mysten SEAL library...');

      // Initialize Sui client
      const suiRpcUrl = process.env.SUI_RPC_URL || 'https://fullnode.testnet.sui.io:443';
      this.suiClient = new SuiClient({ url: suiRpcUrl });

      // Get network from environment or default to testnet
      const network = (process.env.SUI_NETWORK as 'testnet' | 'mainnet') || 'testnet';

      // Get allowlisted key servers for the network
      const keyServerIds = getAllowlistedKeyServers(network);

      // Configure key servers with equal weights
      const serverConfigs: KeyServerConfig[] = keyServerIds.map(objectId => ({
        objectId,
        weight: 1,
      }));

      // Initialize SEAL client
      this.sealClient = new SealClient({
        suiClient: this.suiClient,
        serverConfigs,
        verifyKeyServers: false, // Pre-verified allowlisted servers
        timeout: 10000, // 10 seconds
      });

      this.isInitialized = true;
      this.logger.log('✅ Mysten SEAL library initialized successfully');
      this.logger.log(`Using ${serverConfigs.length} key servers on ${network}`);
    } catch (error) {
      this.logger.error('Failed to initialize SEAL library:', error);
      throw new Error(`SEAL initialization failed: ${error.message}`);
    }
  }

  /**
   * Generate a unique encryption ID for the file
   */
  private generateEncryptionId(): string {
    return `file_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Encrypt file data using Mysten SEAL
   */
  async encryptFile(
    fileData: Buffer | Uint8Array,
    options: SealEncryptionOptions
  ): Promise<EncryptionResult> {
    try {
      if (!this.isInitialized || !this.sealClient) {
        throw new Error('SEAL client not initialized');
      }

      this.logger.log(`Starting Mysten SEAL encryption for file of size: ${fileData.length} bytes`);

      // Convert file data to Uint8Array if needed
      const data = fileData instanceof Buffer ? new Uint8Array(fileData) : fileData;

      // Generate unique encryption ID
      const encryptionId = this.generateEncryptionId();

      // Set default threshold (majority of key servers)
      const threshold = options.threshold || Math.ceil(3); // Default to 3 for security

      // Encrypt the file data
      const result = await this.sealClient.encrypt({
        packageId: options.packageId,
        id: encryptionId,
        data,
        threshold,
        aad: options.additionalData,
      });

      this.logger.log(`✅ File encrypted successfully with Mysten SEAL`);
      this.logger.log(`Encryption ID: ${encryptionId}`);

      return {
        success: true,
        encryptedData: result.encryptedObject,
        symmetricKey: result.key,
        encryptionId,
      };
    } catch (error) {
      this.logger.error('Failed to encrypt file:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Decrypt file data using Mysten SEAL
   */
  async decryptFile(
    encryptedData: Uint8Array,
    sessionKey: SessionKey,
    txBytes: Uint8Array
  ): Promise<DecryptionResult> {
    try {
      if (!this.isInitialized || !this.sealClient) {
        throw new Error('SEAL client not initialized');
      }

      this.logger.log('Starting Mysten SEAL decryption...');

      // Decrypt the file data
      const decryptedData = await this.sealClient.decrypt({
        data: encryptedData,
        sessionKey,
        txBytes,
      });

      this.logger.log(`✅ File decrypted successfully, size: ${decryptedData.length} bytes`);

      return {
        success: true,
        decryptedData,
      };
    } catch (error) {
      this.logger.error('Failed to decrypt file:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Fetch keys for decryption from key servers
   */
  async fetchKeys(
    encryptionIds: string[],
    sessionKey: SessionKey,
    txBytes: Uint8Array,
    threshold: number = 3
  ): Promise<void> {
    try {
      if (!this.isInitialized || !this.sealClient) {
        throw new Error('SEAL client not initialized');
      }

      this.logger.log(`Fetching keys for ${encryptionIds.length} encryption IDs`);

      await this.sealClient.fetchKeys({
        ids: encryptionIds,
        sessionKey,
        txBytes,
        threshold,
      });

      this.logger.log('✅ Keys fetched successfully');
    } catch (error) {
      this.logger.error('Failed to fetch keys:', error);
      throw new Error(`Key fetching failed: ${error.message}`);
    }
  }

  /**
   * Get key servers information
   */
  async getKeyServers() {
    try {
      if (!this.isInitialized || !this.sealClient) {
        throw new Error('SEAL client not initialized');
      }

      return await this.sealClient.getKeyServers();
    } catch (error) {
      this.logger.error('Failed to get key servers:', error);
      throw new Error(`Failed to get key servers: ${error.message}`);
    }
  }

  /**
   * Check if SEAL library is initialized
   */
  isReady(): boolean {
    return this.isInitialized && this.sealClient !== null;
  }

  /**
   * Get Sui client instance
   */
  getSuiClient(): SuiClient {
    return this.suiClient;
  }

  /**
   * Get SEAL library version
   */
  getVersion(): string {
    return '@mysten/seal v0.4.18'; // Return the package version
  }
}
