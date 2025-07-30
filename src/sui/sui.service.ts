import { Injectable, Logger } from '@nestjs/common';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { getZkLoginSignature } from '@mysten/sui/zklogin';
import { defaultZkLoginConfig } from '../config/zklogin.config';
import { ZkLoginProof, EphemeralKeyPair } from '../auth/zklogin.service';
import { AccessControlRule } from '../access-control/access-control.service';

export interface AccessControlInfo {
  fileCid: string;
  owner: string;
  conditionType: string;
  allowedEmails: string[];
  allowedAddresses: string[];
  allowedSuiNS?: string[];
  accessStartTime?: number;
  accessEndTime?: number;
  requireAllConditions: boolean;
  currentAccessCount: number;
  totalUserRecords: number;
}

export interface FileMetadata {
  cid: string;
  filename: string;
  fileSize: number;
  uploadTimestamp: number;
  uploader: string;
  authorizedAddresses: string[];
}

export interface SmartContractConfig {
  packageId: string;
  registryObjectId: string;
}

export interface ZkLoginTransactionParams {
  zkLoginProof: ZkLoginProof;
  ephemeralKeyPair: EphemeralKeyPair;
  userSalt: string;
  jwt: string;
}

@Injectable()
export class SuiService {
  private readonly logger = new Logger(SuiService.name);
  private readonly suiClient: SuiClient;
  private readonly config = defaultZkLoginConfig;

  // In-memory storage for access control data (for development)
  private accessControlStorage = new Map<string, AccessControlInfo>();

  constructor() {
    this.suiClient = new SuiClient({ url: this.config.sui.rpcUrl });
  }

  /**
   * Upload file metadata to SuiCircle smart contract
   */
  async uploadFile(
    zkLoginAddress: string,
    cid: string,
    filename: string,
    fileSize: number
  ): Promise<string> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for uploading file
      const tx = new Transaction();

      // Call upload_file function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::upload_file`,
        arguments: [
          tx.object(this.config.sui.registryId || '0x6'), // Registry object ID
          tx.pure.string(cid),
          tx.pure.string(filename),
          tx.pure.u64(fileSize),
          tx.object('0x6'), // Clock object
        ],
      });

      // For now, return a placeholder transaction digest
      // In a real implementation, you would sign and execute the transaction
      // using the zkLogin proof and ephemeral key pair
      this.logger.log(`Would upload file ${filename} with CID ${cid} for user ${zkLoginAddress}`);

      return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    } catch (error) {
      this.logger.error('Failed to upload file to smart contract', error);
      throw new Error('Failed to upload file to smart contract');
    }
  }

  /**
   * Upload file with zkLogin authentication
   */
  async uploadFileWithZkLogin(
    cid: string,
    filename: string,
    fileSize: number,
    zkLoginParams: ZkLoginTransactionParams
  ): Promise<string> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for uploading file
      const tx = new Transaction();

      // Call upload_file function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::upload_file`,
        arguments: [
          tx.object('0x6'), // Registry object ID (placeholder)
          tx.pure.string(cid),
          tx.pure.string(filename),
          tx.pure.u64(fileSize),
          tx.object('0x6'), // Clock object
        ],
      });

      // Execute transaction with zkLogin signature
      const result = await this.executeZkLoginTransaction(tx, zkLoginParams);

      this.logger.log(`Uploaded file ${filename} with CID ${cid}, transaction: ${result.digest}`);

      return result.digest;
    } catch (error) {
      this.logger.error('Failed to upload file with zkLogin', error);
      throw new Error('Failed to upload file with zkLogin');
    }
  }

  /**
   * Grant access to a file for a specific address
   */
  async grantFileAccess(
    zkLoginAddress: string,
    fileCid: string,
    authorizedAddress: string
  ): Promise<string> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for granting access
      const tx = new Transaction();

      // Call grant_access function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::grant_access`,
        arguments: [
          tx.object('0x6'), // Registry object ID (placeholder)
          tx.pure.string(fileCid),
          tx.pure.address(authorizedAddress),
          tx.object('0x6'), // Clock object
        ],
      });

      // Placeholder transaction digest
      this.logger.log(`Would grant access to file ${fileCid} for address ${authorizedAddress}`);

      return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    } catch (error) {
      this.logger.error('Failed to grant file access', error);
      throw new Error('Failed to grant file access');
    }
  }

  /**
   * Check if an address is authorized to access a file
   */
  async isAuthorizedForFile(
    fileCid: string,
    address: string
  ): Promise<boolean> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Call is_authorized function on smart contract
      const result = await this.suiClient.devInspectTransactionBlock({
        transactionBlock: (() => {
          const tx = new Transaction();
          tx.moveCall({
            target: `${this.config.sui.packageId}::suicircle::is_authorized`,
            arguments: [
              tx.object('0x6'), // Registry object ID (placeholder)
              tx.pure.string(fileCid),
              tx.pure.address(address),
            ],
          });
          return tx;
        })(),
        sender: address,
      });

      // Parse the result (this is a simplified implementation)
      // In a real implementation, you would parse the actual return value
      this.logger.log(`Checking authorization for ${address} on file ${fileCid}`);

      return true; // Placeholder - return actual result from smart contract
    } catch (error) {
      this.logger.error('Failed to check file authorization', error);
      return false;
    }
  }

  /**
   * Get file metadata from smart contract
   */
  async getFileMetadata(fileCid: string): Promise<FileMetadata | null> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Call get_file_metadata function on smart contract
      const result = await this.suiClient.devInspectTransactionBlock({
        transactionBlock: (() => {
          const tx = new Transaction();
          tx.moveCall({
            target: `${this.config.sui.packageId}::suicircle::get_file_metadata`,
            arguments: [
              tx.object(this.config.sui.registryId || '0x6'), // Registry object ID
              tx.pure.string(fileCid),
            ],
          });
          return tx;
        })(),
        sender: '0x0000000000000000000000000000000000000000000000000000000000000000',
      });

      // Parse the result (placeholder implementation)
      this.logger.log(`Getting metadata for file ${fileCid}`);

      // Return placeholder metadata
      return {
        cid: fileCid,
        filename: 'example.txt',
        fileSize: 1024,
        uploadTimestamp: Date.now(),
        uploader: '0x1234567890abcdef',
        authorizedAddresses: ['0x1234567890abcdef'],
      };
    } catch (error) {
      this.logger.error('Failed to get file metadata', error);
      return null;
    }
  }

  /**
   * Revoke access to a file for a specific address
   */
  async revokeFileAccess(
    zkLoginAddress: string,
    fileCid: string,
    addressToRemove: string
  ): Promise<string> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for revoking access
      const tx = new Transaction();

      // Call revoke_access function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::revoke_access`,
        arguments: [
          tx.object('0x6'), // Registry object ID (placeholder)
          tx.pure.string(fileCid),
          tx.pure.address(addressToRemove),
          tx.object('0x6'), // Clock object
        ],
      });

      // Placeholder transaction digest
      this.logger.log(`Would revoke access to file ${fileCid} for address ${addressToRemove}`);

      return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    } catch (error) {
      this.logger.error('Failed to revoke file access', error);
      throw new Error('Failed to revoke file access');
    }
  }

  /**
   * Execute a transaction with zkLogin signature
   */
  private async executeZkLoginTransaction(
    tx: Transaction,
    zkLoginParams: ZkLoginTransactionParams
  ): Promise<{ digest: string }> {
    try {
      // Set sender to the zkLogin address
      const zkLoginAddress = this.deriveZkLoginAddress(
        zkLoginParams.jwt,
        zkLoginParams.userSalt
      );
      tx.setSender(zkLoginAddress);

      // Build the transaction
      const txBytes = await tx.build({ client: this.suiClient });

      // Sign with ephemeral key pair
      const ephemeralSignature = await zkLoginParams.ephemeralKeyPair.keypair.sign(txBytes);

      // Create zkLogin signature
      const zkLoginSignature = getZkLoginSignature({
        inputs: {
          ...zkLoginParams.zkLoginProof,
          addressSeed: this.getAddressSeed(zkLoginParams.jwt, zkLoginParams.userSalt),
        },
        maxEpoch: zkLoginParams.ephemeralKeyPair.maxEpoch,
        userSignature: ephemeralSignature,
      });

      // Execute the transaction
      const result = await this.suiClient.executeTransactionBlock({
        transactionBlock: txBytes,
        signature: zkLoginSignature,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new Error(`Transaction failed: ${result.effects?.status?.error}`);
      }

      return { digest: result.digest };
    } catch (error) {
      this.logger.error('Failed to execute zkLogin transaction', error);
      throw new Error('Failed to execute zkLogin transaction');
    }
  }

  /**
   * Derive zkLogin address from JWT and salt
   */
  private deriveZkLoginAddress(jwt: string, salt: string): string {
    // This is a simplified implementation
    // The actual implementation would use the zkLogin address derivation algorithm
    // which involves hashing the JWT claims with the salt

    // For now, return a placeholder address
    // In production, use the actual zkLogin address derivation
    const addressSeed = this.getAddressSeed(jwt, salt);

    // This should be replaced with actual zkLogin address derivation
    return `0x${Buffer.from(addressSeed).toString('hex').slice(0, 40)}`;
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
   * Grant file access with zkLogin authentication
   */
  async grantFileAccessWithZkLogin(
    fileCid: string,
    authorizedAddress: string,
    zkLoginParams: ZkLoginTransactionParams
  ): Promise<string> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for granting access
      const tx = new Transaction();

      // Call grant_access function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::grant_access`,
        arguments: [
          tx.object('0x6'), // Registry object ID (placeholder)
          tx.pure.string(fileCid),
          tx.pure.address(authorizedAddress),
          tx.object('0x6'), // Clock object
        ],
      });

      // Execute transaction with zkLogin signature
      const result = await this.executeZkLoginTransaction(tx, zkLoginParams);

      this.logger.log(`Granted access to file ${fileCid} for address ${authorizedAddress}`);

      return result.digest;
    } catch (error) {
      this.logger.error('Failed to grant file access with zkLogin', error);
      throw new Error('Failed to grant file access with zkLogin');
    }
  }

  /**
   * Revoke file access with zkLogin authentication
   */
  async revokeFileAccessWithZkLogin(
    fileCid: string,
    addressToRemove: string,
    zkLoginParams: ZkLoginTransactionParams
  ): Promise<string> {
    try {
      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for revoking access
      const tx = new Transaction();

      // Call revoke_access function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::revoke_access`,
        arguments: [
          tx.object('0x6'), // Registry object ID (placeholder)
          tx.pure.string(fileCid),
          tx.pure.address(addressToRemove),
          tx.object('0x6'), // Clock object
        ],
      });

      // Execute transaction with zkLogin signature
      const result = await this.executeZkLoginTransaction(tx, zkLoginParams);

      this.logger.log(`Revoked access to file ${fileCid} for address ${addressToRemove}`);

      return result.digest;
    } catch (error) {
      this.logger.error('Failed to revoke file access with zkLogin', error);
      throw new Error('Failed to revoke file access with zkLogin');
    }
  }

  /**
   * Create access control for a file
   */
  async createFileAccessControl(
    zkLoginAddress: string,
    fileCid: string,
    accessRule: AccessControlRule
  ): Promise<string> {
    try {
      this.logger.log(`Creating access control for file ${fileCid} by ${zkLoginAddress}`);

      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for creating access control
      const tx = new Transaction();

      // Prepare email addresses as vector of bytes
      const emailBytes = (accessRule.allowedEmails || []).map(email =>
        Array.from(new TextEncoder().encode(email))
      );

      // Prepare wallet addresses
      const allowedAddresses = accessRule.allowedAddresses || [];

      // Prepare SuiNS names as vector of bytes
      const suiNSBytes = (accessRule.allowedSuiNS || []).map(name =>
        Array.from(new TextEncoder().encode(name))
      );

      // Call create_file_access_control function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::create_file_access_control`,
        arguments: [
          tx.pure.vector('u8', Array.from(new TextEncoder().encode(fileCid))), // file_cid as vector<u8>
          tx.pure.vector('u8', Array.from(new TextEncoder().encode(accessRule.conditionType))), // condition_type as vector<u8>
          tx.pure.vector('vector<u8>', emailBytes), // allowed_emails as vector<vector<u8>>
          tx.pure.vector('address', allowedAddresses), // allowed_addresses as vector<address>
          tx.pure.vector('vector<u8>', suiNSBytes), // allowed_suins_names as vector<vector<u8>>
          accessRule.accessStartTime ? tx.pure.option('u64', accessRule.accessStartTime) : tx.pure.option('u64', null),
          accessRule.accessEndTime ? tx.pure.option('u64', accessRule.accessEndTime) : tx.pure.option('u64', null),
          accessRule.maxAccessDuration ? tx.pure.option('u64', accessRule.maxAccessDuration) : tx.pure.option('u64', null),
          tx.pure.bool(accessRule.requireAllConditions || false),
          accessRule.maxAccessCount ? tx.pure.option('u64', accessRule.maxAccessCount) : tx.pure.option('u64', null),
          tx.object('0x6'), // Clock object
        ],
      });

      // Store access control data in memory (for development)
      const accessControlInfo: AccessControlInfo = {
        fileCid,
        owner: zkLoginAddress,
        conditionType: accessRule.conditionType,
        allowedEmails: accessRule.allowedEmails || [],
        allowedAddresses: accessRule.allowedAddresses || [],
        allowedSuiNS: accessRule.allowedSuiNS || [],
        accessStartTime: accessRule.accessStartTime,
        accessEndTime: accessRule.accessEndTime,
        requireAllConditions: accessRule.requireAllConditions || false,
        currentAccessCount: 0,
        totalUserRecords: 0,
      };

      this.accessControlStorage.set(fileCid, accessControlInfo);

      // For now, return a simulated transaction digest since we need zkLogin signing
      // In a full implementation, this would be signed with zkLogin proof
      const simulatedDigest = `sui_tx_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

      this.logger.log(`Access control creation transaction prepared for file ${fileCid}: ${simulatedDigest}`);
      this.logger.log(`Transaction would be signed by: ${zkLoginAddress}`);
      this.logger.log(`Stored access control data:`, accessControlInfo);

      return simulatedDigest;
    } catch (error) {
      this.logger.error('Failed to create file access control', error);
      throw new Error(`Failed to create file access control: ${error.message}`);
    }
  }

  /**
   * Update access control for a file
   */
  async updateFileAccessControl(
    zkLoginAddress: string,
    fileCid: string,
    accessRule: AccessControlRule
  ): Promise<string> {
    try {
      this.logger.log(`Updating access control for file ${fileCid} by ${zkLoginAddress}`);

      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Create transaction for updating access control
      const tx = new Transaction();

      // Prepare email addresses as vector of bytes
      const emailBytes = (accessRule.allowedEmails || []).map(email =>
        Array.from(new TextEncoder().encode(email))
      );

      // Prepare wallet addresses
      const allowedAddresses = accessRule.allowedAddresses || [];

      // Prepare SuiNS names as vector of bytes
      const suiNSBytes = (accessRule.allowedSuiNS || []).map(name =>
        Array.from(new TextEncoder().encode(name))
      );

      // Call update_file_access_control function on smart contract
      tx.moveCall({
        target: `${this.config.sui.packageId}::suicircle::update_file_access_control`,
        arguments: [
          tx.pure.string(fileCid), // Find the access control object by file CID (this would need to be improved)
          tx.pure.vector('u8', Array.from(new TextEncoder().encode(accessRule.conditionType))),
          tx.pure.vector('vector<u8>', emailBytes), // vector<vector<u8>>
          tx.pure.vector('address', allowedAddresses), // vector<address>
          tx.pure.vector('vector<u8>', suiNSBytes), // allowed_suins_names as vector<vector<u8>>
          accessRule.accessStartTime ? tx.pure.option('u64', accessRule.accessStartTime) : tx.pure.option('u64', null),
          accessRule.accessEndTime ? tx.pure.option('u64', accessRule.accessEndTime) : tx.pure.option('u64', null),
          accessRule.maxAccessDuration ? tx.pure.option('u64', accessRule.maxAccessDuration) : tx.pure.option('u64', null),
          tx.pure.bool(accessRule.requireAllConditions || false),
          accessRule.maxAccessCount ? tx.pure.option('u64', accessRule.maxAccessCount) : tx.pure.option('u64', null),
          tx.object('0x6'), // Clock object
        ],
      });

      // Update access control data in memory (for development)
      const accessControlInfo: AccessControlInfo = {
        fileCid,
        owner: zkLoginAddress,
        conditionType: accessRule.conditionType,
        allowedEmails: accessRule.allowedEmails || [],
        allowedAddresses: accessRule.allowedAddresses || [],
        allowedSuiNS: accessRule.allowedSuiNS || [],
        accessStartTime: accessRule.accessStartTime,
        accessEndTime: accessRule.accessEndTime,
        requireAllConditions: accessRule.requireAllConditions || false,
        currentAccessCount: 0,
        totalUserRecords: 0,
      };

      this.accessControlStorage.set(fileCid, accessControlInfo);

      // For now, return a simulated transaction digest since we need zkLogin signing
      // In a full implementation, this would be signed with zkLogin proof
      const simulatedDigest = `sui_tx_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

      this.logger.log(`Access control update transaction prepared for file ${fileCid}: ${simulatedDigest}`);
      this.logger.log(`Transaction would be signed by: ${zkLoginAddress}`);
      this.logger.log(`Updated access control data:`, accessControlInfo);

      return simulatedDigest;
    } catch (error) {
      this.logger.error('Failed to update file access control', error);
      throw new Error(`Failed to update file access control: ${error.message}`);
    }
  }

  /**
   * Validate file access for a user
   */
  async validateFileAccess(
    fileCid: string,
    userAddress: string,
    userEmail?: string,
    userSuiNS?: string
  ): Promise<boolean> {
    try {
      this.logger.log(`Validating access for file ${fileCid} by ${userAddress}`);

      if (!this.config.sui.packageId) {
        this.logger.warn('SuiCircle package ID not configured, granting access for development');
        return true;
      }

      // Get access control info for the file
      const accessControlInfo = await this.getFileAccessControlInfo(fileCid);

      if (!accessControlInfo) {
        this.logger.log(`No access control found for file ${fileCid}, granting access`);
        return true;
      }

      // Check wallet address access
      let addressValid = false;
      if (accessControlInfo.allowedAddresses.length === 0 ||
          accessControlInfo.allowedAddresses.includes(userAddress)) {
        addressValid = true;
      }

      // Check email access
      let emailValid = false;
      if (accessControlInfo.allowedEmails.length === 0) {
        emailValid = true;
      } else if (userEmail && accessControlInfo.allowedEmails.includes(userEmail)) {
        emailValid = true;
      }

      // Check SuiNS access (if supported)
      let suiNSValid = false;
      if (!accessControlInfo.allowedSuiNS || accessControlInfo.allowedSuiNS.length === 0) {
        suiNSValid = true;
      } else if (userSuiNS && accessControlInfo.allowedSuiNS.includes(userSuiNS)) {
        suiNSValid = true;
      }

      // Check time-based access
      let timeValid = true;
      const now = Date.now();
      if (accessControlInfo.accessStartTime && now < accessControlInfo.accessStartTime) {
        timeValid = false;
      }
      if (accessControlInfo.accessEndTime && now > accessControlInfo.accessEndTime) {
        timeValid = false;
      }

      // Apply logic (AND vs OR)
      const accessGranted = accessControlInfo.requireAllConditions
        ? (addressValid && emailValid && suiNSValid && timeValid)
        : (addressValid || emailValid || suiNSValid) && timeValid;

      this.logger.log(`Access validation result for file ${fileCid}: ${accessGranted}`);
      this.logger.log(`Address valid: ${addressValid}, Email valid: ${emailValid}, SuiNS valid: ${suiNSValid}, Time valid: ${timeValid}`);

      return accessGranted;
    } catch (error) {
      this.logger.error('Failed to validate file access', error);
      // In case of error, grant access for development but log the issue
      this.logger.warn('Granting access due to validation error (development mode)');
      return true;
    }
  }

  /**
   * Get access control information for a file
   */
  async getFileAccessControlInfo(fileCid: string): Promise<AccessControlInfo | null> {
    try {
      this.logger.log(`Getting access control info for file ${fileCid}`);

      if (!this.config.sui.packageId) {
        throw new Error('SuiCircle package ID not configured');
      }

      // Query for FileAccessControl objects with matching file_cid
      // This is a simplified approach - in production, you'd want to maintain an index
      try {
        const objects = await this.suiClient.getOwnedObjects({
          owner: this.config.sui.registryId || '0x6', // This would need to be the actual registry or a way to find access control objects
          filter: {
            StructType: `${this.config.sui.packageId}::suicircle::FileAccessControl`
          },
          options: {
            showContent: true,
            showType: true,
          }
        });

        // Find the access control object for this file
        for (const obj of objects.data) {
          if (obj.data?.content && 'fields' in obj.data.content) {
            const fields = obj.data.content.fields as any;
            if (fields.file_cid === fileCid) {
              // Parse the access control data
              const accessCondition = fields.access_condition;

              return {
                fileCid: fields.file_cid,
                owner: fields.owner,
                conditionType: accessCondition.condition_type,
                allowedEmails: accessCondition.allowed_emails || [],
                allowedAddresses: accessCondition.allowed_addresses || [],
                allowedSuiNS: [], // SuiNS support would be added here
                accessStartTime: accessCondition.access_start_time,
                accessEndTime: accessCondition.access_end_time,
                requireAllConditions: accessCondition.require_all_conditions,
                currentAccessCount: accessCondition.current_access_count,
                totalUserRecords: fields.user_access_records?.length || 0,
              };
            }
          }
        }
      } catch (queryError) {
        this.logger.warn(`Could not query smart contract for file ${fileCid}, returning mock data: ${queryError.message}`);
      }

      // Check if we have stored access control data for this file
      const storedInfo = this.accessControlStorage.get(fileCid);
      if (storedInfo) {
        this.logger.log(`Access control info retrieved for file ${fileCid} from storage`);
        return storedInfo;
      }

      // Return null if no access control found
      this.logger.log(`No access control found for file ${fileCid}`);
      return null;
    } catch (error) {
      this.logger.error('Failed to get file access control info', error);
      return null;
    }
  }
}
