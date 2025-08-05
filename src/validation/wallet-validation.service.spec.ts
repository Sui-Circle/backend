import { Test, TestingModule } from '@nestjs/testing';
import { WalletValidationService } from './wallet-validation.service';
import { AuthenticatedUser } from '../auth/zklogin.service';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { OAuthProvider } from '../config/zklogin.config';

describe('WalletValidationService', () => {
  let service: WalletValidationService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [WalletValidationService],
    }).compile();

    service = module.get<WalletValidationService>(WalletValidationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateZkLoginAuthentication', () => {
    it('should pass validation for complete zkLogin user', () => {
      const mockUser: AuthenticatedUser = {
        sub: 'test-user',
        aud: 'test-audience',
        iss: 'https://github.com',
        email: 'test@example.com',
        provider: OAuthProvider.GITHUB,
        zkLoginAddress: '0x1234567890123456789012345678901234567890',
        ephemeralKeyPair: {
          keypair: new Ed25519Keypair(),
          maxEpoch: 1000,
          randomness: 'test-randomness',
        },
        zkLoginProof: {
          proofPoints: {
            a: ['test-a'],
            b: [['test-b']],
            c: ['test-c'],
          },
          issBase64Details: {
            value: 'test-value',
            indexMod4: 0,
          },
          headerBase64: 'test-header',
        },
        jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiZ2l0aHViLmNvbSIsImV4cCI6OTk5OTk5OTk5OX0.test',
        userSalt: 'test-salt',
      };

      const result = service.validateZkLoginAuthentication(mockUser);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.userAddress).toBe(mockUser.zkLoginAddress);
    });

    it('should fail validation for missing zkLogin parameters', () => {
      const mockUser: AuthenticatedUser = {
        sub: 'test-user',
        aud: 'test-audience',
        iss: 'https://github.com',
        email: 'test@example.com',
        provider: OAuthProvider.GITHUB,
        zkLoginAddress: '0x1234567890123456789012345678901234567890',
        // Missing required zkLogin parameters
      };

      const result = service.validateZkLoginAuthentication(mockUser);

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors).toContain('Ephemeral key pair is missing');
      expect(result.errors).toContain('zkLogin proof is missing');
      expect(result.errors).toContain('JWT token is missing');
      expect(result.errors).toContain('User salt is missing');
    });

    it('should fail validation for invalid JWT format', () => {
      const mockUser: AuthenticatedUser = {
        sub: 'test-user',
        aud: 'test-audience',
        iss: 'https://github.com',
        email: 'test@example.com',
        provider: OAuthProvider.GITHUB,
        zkLoginAddress: '0x1234567890123456789012345678901234567890',
        ephemeralKeyPair: {
          keypair: new Ed25519Keypair(),
          maxEpoch: 1000,
          randomness: 'test-randomness',
        },
        zkLoginProof: {
          proofPoints: {
            a: ['test-a'],
            b: [['test-b']],
            c: ['test-c'],
          },
          issBase64Details: {
            value: 'test-value',
            indexMod4: 0,
          },
          headerBase64: 'test-header',
        },
        jwt: 'invalid-jwt-format', // Invalid JWT
        userSalt: 'test-salt',
      };

      const result = service.validateZkLoginAuthentication(mockUser);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('JWT format is invalid (should have 3 parts)');
    });
  });

  describe('validateTransactionSigner', () => {
    it('should pass validation for matching addresses', () => {
      const userAddress = '0x1234567890123456789012345678901234567890';
      const signerAddress = '0x1234567890123456789012345678901234567890';

      const result = service.validateTransactionSigner(userAddress, signerAddress);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should fail validation for mismatched addresses', () => {
      const userAddress = '0x1234567890123456789012345678901234567890';
      const signerAddress = '0x9876543210987654321098765432109876543210';

      const result = service.validateTransactionSigner(userAddress, signerAddress);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        `Transaction signer mismatch: expected ${userAddress}, got ${signerAddress}`
      );
    });

    it('should fail validation for missing addresses', () => {
      const result = service.validateTransactionSigner('', '');

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Expected user address is missing');
      expect(result.errors).toContain('Actual signer address is missing');
    });
  });

  describe('validateNoAdminAddressUsage', () => {
    it('should pass validation for non-admin address', () => {
      const userAddress = '0x1234567890123456789012345678901234567890';
      const operationType = 'file_upload';

      const result = service.validateNoAdminAddressUsage(userAddress, operationType);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    // Note: Testing admin address detection would require setting up environment variables
    // which is complex in unit tests. This would be better tested in integration tests.
  });
});
