import { Test, TestingModule } from '@nestjs/testing';
import { ZkLoginService } from './zklogin.service';
import { OAuthProvider } from '../config/zklogin.config';
import * as jose from 'jose';

// Mock the zklogin module
jest.mock('@mysten/sui/zklogin', () => ({
  generateNonce: jest.fn().mockReturnValue('mock-nonce'),
  getExtendedEphemeralPublicKey: jest.fn().mockReturnValue('mock-extended-key'),
  jwtToAddress: jest.fn().mockReturnValue('0x1234567890abcdef'),
  generateRandomness: jest.fn().mockReturnValue('mock-randomness'),
}));

// Mock SuiClient
jest.mock('@mysten/sui/client', () => ({
  SuiClient: jest.fn().mockImplementation(() => ({
    getLatestSuiSystemState: jest.fn().mockResolvedValue({
      epoch: '100',
    }),
  })),
}));

// Mock Ed25519Keypair
jest.mock('@mysten/sui/keypairs/ed25519', () => ({
  Ed25519Keypair: {
    generate: jest.fn().mockReturnValue({
      getPublicKey: jest.fn().mockReturnValue({
        toSuiPublicKey: jest.fn().mockReturnValue('mock-public-key'),
        toSuiBytes: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3])),
      }),
    }),
  },
}));

// Mock jose
jest.mock('jose', () => ({
  decodeJwt: jest.fn(),
}));

// Mock fetch
global.fetch = jest.fn();

describe('ZkLoginService', () => {
  let service: ZkLoginService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ZkLoginService],
    }).compile();

    service = module.get<ZkLoginService>(ZkLoginService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateEphemeralKeyPair', () => {
    it('should generate ephemeral key pair with valid properties', async () => {
      const keyPair = await service.generateEphemeralKeyPair();

      expect(keyPair).toHaveProperty('keypair');
      expect(keyPair).toHaveProperty('maxEpoch');
      expect(keyPair).toHaveProperty('randomness');
      expect(typeof keyPair.maxEpoch).toBe('number');
      expect(keyPair.maxEpoch).toBeGreaterThan(0);
      expect(typeof keyPair.randomness).toBe('string');
    });
  });

  describe('createZkLoginSession', () => {
    it('should create zkLogin session for Google provider', async () => {
      const result = await service.createZkLoginSession(OAuthProvider.GOOGLE);

      expect(result).toHaveProperty('authUrl');
      expect(result).toHaveProperty('session');
      expect(result.authUrl).toContain('accounts.google.com');
      expect(result.session.provider).toBe(OAuthProvider.GOOGLE);
      expect(result.session).toHaveProperty('ephemeralKeyPair');
      expect(result.session).toHaveProperty('nonce');
      expect(result.session).toHaveProperty('maxEpoch');
      expect(result.session).toHaveProperty('userSalt');
    });

    it('should create zkLogin session for Facebook provider', async () => {
      const result = await service.createZkLoginSession(OAuthProvider.FACEBOOK);

      expect(result.authUrl).toContain('facebook.com');
      expect(result.session.provider).toBe(OAuthProvider.FACEBOOK);
    });

    it('should create zkLogin session for Twitch provider', async () => {
      const result = await service.createZkLoginSession(OAuthProvider.TWITCH);

      expect(result.authUrl).toContain('id.twitch.tv');
      expect(result.session.provider).toBe(OAuthProvider.TWITCH);
    });

    it('should handle errors during session creation', async () => {
      // Mock an error in key generation
      jest.spyOn(service, 'generateEphemeralKeyPair').mockRejectedValue(new Error('Key generation failed'));

      await expect(service.createZkLoginSession(OAuthProvider.GOOGLE)).rejects.toThrow(
        'Failed to create zkLogin session'
      );
    });
  });

  describe('verifyJwtToken', () => {
    it('should verify valid Google JWT token', async () => {
      const mockDecodedJwt = {
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
        email: 'test@example.com',
        name: 'Test User',
      };

      (jose.decodeJwt as jest.Mock).mockReturnValue(mockDecodedJwt);

      const result = await service.verifyJwtToken('mock-jwt-token', OAuthProvider.GOOGLE);

      expect(result).toEqual(mockDecodedJwt);
      expect(jose.decodeJwt).toHaveBeenCalledWith('mock-jwt-token');
    });

    it('should verify valid Facebook JWT token', async () => {
      const mockDecodedJwt = {
        sub: 'facebook-user-id',
        aud: 'client-id',
        iss: 'https://www.facebook.com',
        email: 'test@example.com',
        name: 'Test User',
      };

      (jose.decodeJwt as jest.Mock).mockReturnValue(mockDecodedJwt);

      const result = await service.verifyJwtToken('mock-jwt-token', OAuthProvider.FACEBOOK);

      expect(result).toEqual(mockDecodedJwt);
    });

    it('should reject JWT with missing required fields', async () => {
      const mockDecodedJwt = {
        sub: 'user-id',
        // Missing aud and iss
      };

      (jose.decodeJwt as jest.Mock).mockReturnValue(mockDecodedJwt);

      await expect(service.verifyJwtToken('mock-jwt-token', OAuthProvider.GOOGLE)).rejects.toThrow(
        'Failed to verify JWT token'
      );
    });

    it('should reject JWT with invalid issuer', async () => {
      const mockDecodedJwt = {
        sub: 'user-id',
        aud: 'client-id',
        iss: 'https://malicious.com', // Invalid issuer
      };

      (jose.decodeJwt as jest.Mock).mockReturnValue(mockDecodedJwt);

      await expect(service.verifyJwtToken('mock-jwt-token', OAuthProvider.GOOGLE)).rejects.toThrow(
        'Failed to verify JWT token'
      );
    });

    it('should handle JWT decoding errors', async () => {
      (jose.decodeJwt as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid JWT');
      });

      await expect(service.verifyJwtToken('invalid-jwt', OAuthProvider.GOOGLE)).rejects.toThrow(
        'Failed to verify JWT token'
      );
    });
  });

  describe('exchangeCodeForToken', () => {
    it('should exchange Google OAuth code for JWT token', async () => {
      const mockTokenResponse = {
        access_token: 'access-token',
        id_token: 'jwt-token',
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockTokenResponse),
      });

      const result = await service.exchangeCodeForToken(OAuthProvider.GOOGLE, 'oauth-code');

      expect(result).toBe('jwt-token');
      expect(global.fetch).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        })
      );
    });

    it('should handle token exchange errors', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        statusText: 'Bad Request',
      });

      await expect(
        service.exchangeCodeForToken(OAuthProvider.GOOGLE, 'invalid-code')
      ).rejects.toThrow('Failed to exchange OAuth code for token');
    });

    it('should handle network errors', async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

      await expect(
        service.exchangeCodeForToken(OAuthProvider.GOOGLE, 'oauth-code')
      ).rejects.toThrow('Failed to exchange OAuth code for token');
    });
  });

  describe('generateZkLoginProof', () => {
    it('should generate zkLogin proof successfully', async () => {
      const mockProof = {
        proofPoints: {
          a: ['0x1', '0x2'],
          b: [['0x3', '0x4'], ['0x5', '0x6']],
          c: ['0x7', '0x8'],
        },
        issBase64Details: {
          value: 'base64-value',
          indexMod4: 1,
        },
        headerBase64: 'header-base64',
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockProof),
      });

      const mockEphemeralKeyPair = {
        keypair: {
          getPublicKey: () => ({
            toSuiPublicKey: () => 'mock-public-key',
            toSuiBytes: () => new Uint8Array([1, 2, 3])
          }),
        } as any,
        maxEpoch: 100,
        randomness: 'test-randomness',
      };

      const result = await service.generateZkLoginProof(
        'jwt-token',
        mockEphemeralKeyPair,
        'user-salt'
      );

      expect(result).toEqual(mockProof);
    });

    it('should handle prover service errors', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        statusText: 'Internal Server Error',
      });

      const mockEphemeralKeyPair = {
        keypair: {
          getPublicKey: () => ({
            toSuiPublicKey: () => 'mock-public-key',
            toSuiBytes: () => new Uint8Array([1, 2, 3])
          }),
        } as any,
        maxEpoch: 100,
        randomness: 'test-randomness',
      };

      await expect(
        service.generateZkLoginProof('jwt-token', mockEphemeralKeyPair, 'user-salt')
      ).rejects.toThrow('Failed to generate zkLogin proof');
    });
  });

  describe('completeAuthentication', () => {
    it('should complete authentication successfully', async () => {
      const mockSession = {
        ephemeralKeyPair: {
          keypair: {
            getPublicKey: () => ({
              toSuiPublicKey: () => 'mock-public-key',
              toSuiBytes: () => new Uint8Array([1, 2, 3])
            }),
          } as any,
          maxEpoch: 100,
          randomness: 'test-randomness',
        },
        nonce: 'test-nonce',
        provider: OAuthProvider.GOOGLE,
        maxEpoch: 100,
        userSalt: 'test-salt',
      };

      const mockDecodedJwt = {
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
        email: 'test@example.com',
        name: 'Test User',
      };

      const mockProof = {
        proofPoints: {
          a: ['0x1', '0x2'],
          b: [['0x3', '0x4'], ['0x5', '0x6']],
          c: ['0x7', '0x8'],
        },
        issBase64Details: {
          value: 'base64-value',
          indexMod4: 1,
        },
        headerBase64: 'header-base64',
      };

      (jose.decodeJwt as jest.Mock).mockReturnValue(mockDecodedJwt);
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockProof),
      });

      const result = await service.completeAuthentication(mockSession, 'jwt-token');

      expect(result).toHaveProperty('zkLoginAddress');
      expect(result).toHaveProperty('provider');
      expect(result).toHaveProperty('email');
      expect(result).toHaveProperty('name');
      expect(result).toHaveProperty('sub');
      expect(result).toHaveProperty('aud');
      expect(result).toHaveProperty('iss');
      expect(result.provider).toBe(OAuthProvider.GOOGLE);
      expect(result.email).toBe('test@example.com');
      expect(result.name).toBe('Test User');
    });

    it('should handle authentication completion errors', async () => {
      const mockSession = {
        ephemeralKeyPair: {
          keypair: {
            getPublicKey: () => ({
              toSuiPublicKey: () => 'mock-public-key',
              toSuiBytes: () => new Uint8Array([1, 2, 3])
            }),
          } as any,
          maxEpoch: 100,
          randomness: 'test-randomness',
        },
        nonce: 'test-nonce',
        provider: OAuthProvider.GOOGLE,
        maxEpoch: 100,
        userSalt: 'test-salt',
      };

      (jose.decodeJwt as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid JWT');
      });

      await expect(service.completeAuthentication(mockSession, 'invalid-jwt')).rejects.toThrow(
        'Failed to complete authentication'
      );
    });
  });
});
