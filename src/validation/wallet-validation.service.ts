import { Injectable, Logger } from '@nestjs/common';
import { AuthenticatedUser } from '../auth/zklogin.service';
import { WalletUser } from '../auth/auth.service';

export interface WalletValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  userAddress?: string;
}

@Injectable()
export class WalletValidationService {
  private readonly logger = new Logger(WalletValidationService.name);

  private isZkLoginUser(user: AuthenticatedUser | WalletUser): user is AuthenticatedUser {
    return 'zkLoginAddress' in user;
  }

  private getUserAddress(user: AuthenticatedUser | WalletUser): string {
    return 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;
  }

  /**
   * Validate wallet authentication
   */
  validateWalletAuthentication(user: WalletUser): WalletValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!user.walletAddress) {
      errors.push('Wallet address is missing');
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      userAddress: user.walletAddress
    };
  }

  /**
   * Validate that user has proper zkLogin authentication for wallet operations
   * This method now handles both zkLogin and wallet authentication
   */
  validateZkLoginAuthentication(user: AuthenticatedUser | WalletUser): WalletValidationResult {
    // Check if it's a wallet user
    if ('walletAddress' in user) {
      return this.validateWalletAuthentication(user as WalletUser);
    }
    
    // For zkLogin users, continue with the original validation
    const errors: string[] = [];
    const warnings: string[] = [];
    const isDevelopment = process.env.NODE_ENV !== 'production';

    // Check required zkLogin parameters
    if (!user.ephemeralKeyPair) {
      errors.push('Ephemeral key pair is missing');
    }

    if (!user.zkLoginProof) {
      errors.push('zkLogin proof is missing');
    }

    if (!user.jwt) {
      errors.push('JWT token is missing');
    }

    if (!user.userSalt) {
      errors.push('User salt is missing');
    }

    // Only check zkLoginAddress if it's a zkLogin user
    if ('zkLoginAddress' in user && !user.zkLoginAddress) {
      errors.push('zkLogin address is missing');
    }

    // Check ephemeral key pair validity
    if (user.ephemeralKeyPair) {
      if (!user.ephemeralKeyPair.keypair) {
        errors.push('Ephemeral keypair object is invalid');
      }

      if (!user.ephemeralKeyPair.maxEpoch || user.ephemeralKeyPair.maxEpoch <= 0) {
        errors.push('Invalid or missing maxEpoch in ephemeral key pair');
      }

      if (!user.ephemeralKeyPair.randomness) {
        errors.push('Missing randomness in ephemeral key pair');
      }

      // Check if ephemeral key pair is expired
      const currentEpoch = Math.floor(Date.now() / 1000 / 86400); // Rough epoch calculation
      if (user.ephemeralKeyPair.maxEpoch < currentEpoch) {
        warnings.push('Ephemeral key pair may be expired');
      }
    }

    // Check zkLogin proof structure
    if (user.zkLoginProof) {
      if (!user.zkLoginProof.proofPoints) {
        errors.push('zkLogin proof points are missing');
      } else {
        if (!user.zkLoginProof.proofPoints.a || !Array.isArray(user.zkLoginProof.proofPoints.a)) {
          errors.push('zkLogin proof point A is invalid');
        }
        if (!user.zkLoginProof.proofPoints.b || !Array.isArray(user.zkLoginProof.proofPoints.b)) {
          errors.push('zkLogin proof point B is invalid');
        }
        if (!user.zkLoginProof.proofPoints.c || !Array.isArray(user.zkLoginProof.proofPoints.c)) {
          errors.push('zkLogin proof point C is invalid');
        }
      }

      if (!user.zkLoginProof.issBase64Details) {
        errors.push('zkLogin issuer base64 details are missing');
      }

      if (!user.zkLoginProof.headerBase64) {
        errors.push('zkLogin header base64 is missing');
      }
    }

    // Validate JWT structure
    if (user.jwt) {
      try {
        const jwtParts = user.jwt.split('.');
        if (jwtParts.length !== 3) {
          errors.push('JWT format is invalid (should have 3 parts)');
        } else {
          // Try to decode the payload
          const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64').toString());
          
          if (!payload.sub) {
            errors.push('JWT subject (sub) is missing');
          }

          if (!payload.iss) {
            errors.push('JWT issuer (iss) is missing');
          }

          if (!payload.exp) {
            warnings.push('JWT expiration (exp) is missing');
          } else if (payload.exp < Math.floor(Date.now() / 1000)) {
            warnings.push('JWT token appears to be expired');
          }
        }
      } catch (error) {
        errors.push('JWT payload cannot be decoded');
      }
    }

    // Get user address (either wallet or zkLogin)
    const userAddress = this.getUserAddress(user);
    
    // Validate zkLogin address format if it's a zkLogin user
    if ('zkLoginAddress' in user && user.zkLoginAddress) {
      if (!user.zkLoginAddress.startsWith('0x')) {
        errors.push('zkLogin address should start with 0x');
      }

      if (user.zkLoginAddress.length !== 42) {
        warnings.push('zkLogin address length is unusual (expected 42 characters)');
      }
    }

    const isValid = errors.length === 0;

    if (!isValid) {
      this.logger.error('Authentication validation failed:', {
        errors,
        warnings,
        userAddress,
      });
    } else if (warnings.length > 0) {
      this.logger.warn('Authentication validation has warnings:', {
        warnings,
        userAddress,
      });
    } else {
      this.logger.log(`✅ Authentication validation passed for address: ${userAddress}`);
    }

    return {
      isValid,
      errors,
      warnings,
      userAddress,
    };
  }

  /**
   * Validate that a transaction is properly signed by the expected user
   */
  validateTransactionSigner(
    expectedUserAddress: string,
    actualSignerAddress: string
  ): WalletValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!expectedUserAddress) {
      errors.push('Expected user address is missing');
    }

    if (!actualSignerAddress) {
      errors.push('Actual signer address is missing');
    }

    if (expectedUserAddress && actualSignerAddress) {
      if (expectedUserAddress.toLowerCase() !== actualSignerAddress.toLowerCase()) {
        errors.push(`Transaction signer mismatch: expected ${expectedUserAddress}, got ${actualSignerAddress}`);
      }
    }

    const isValid = errors.length === 0;

    if (!isValid) {
      this.logger.error('Transaction signer validation failed:', {
        expectedUserAddress,
        actualSignerAddress,
        errors,
      });
    } else {
      this.logger.log(`✅ Transaction signer validation passed: ${actualSignerAddress}`);
    }

    return {
      isValid,
      errors,
      warnings,
      userAddress: actualSignerAddress,
    };
  }

  /**
   * Validate that no hardcoded admin addresses are being used for user operations
   */
  validateNoAdminAddressUsage(
    userAddress: string,
    operationType: string
  ): WalletValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // List of known admin/system addresses that should not be used for user operations
    const adminAddresses = [
      process.env.WALRUS_PRIVATE_KEY ? this.deriveAddressFromPrivateKey(process.env.WALRUS_PRIVATE_KEY) : null,
      process.env.SPONSOR_PRIVATE_KEY ? this.deriveAddressFromPrivateKey(process.env.SPONSOR_PRIVATE_KEY) : null,
    ].filter(Boolean);

    if (adminAddresses.includes(userAddress)) {
      errors.push(`User operation ${operationType} is using admin address: ${userAddress}`);
    }

    const isValid = errors.length === 0;

    if (!isValid) {
      this.logger.error(`Admin address usage detected in ${operationType}:`, {
        userAddress,
        operationType,
        errors,
      });
    }

    return {
      isValid,
      errors,
      warnings,
      userAddress,
    };
  }

  /**
   * Helper method to derive address from private key (simplified)
   */
  private deriveAddressFromPrivateKey(privateKey: string): string | null {
    try {
      // This is a simplified implementation
      // In production, you would use proper Sui SDK methods
      const hash = require('crypto').createHash('sha256').update(privateKey).digest('hex');
      return `0x${hash.substring(0, 40)}`;
    } catch (error) {
      return null;
    }
  }
}
