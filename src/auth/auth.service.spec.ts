import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { ZkLoginService } from './zklogin.service';
import { SuiService } from '../sui/sui.service';

describe('AuthService', () => {
  let service: AuthService;
  let zkLoginService: ZkLoginService;

  const mockZkLoginService = {
    createZkLoginSession: jest.fn(),
    exchangeCodeForToken: jest.fn(),
    completeAuthentication: jest.fn(),
  };

  const mockSuiService = {
    // Add any SuiService methods that might be used
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: ZkLoginService,
          useValue: mockZkLoginService,
        },
        {
          provide: SuiService,
          useValue: mockSuiService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    zkLoginService = module.get<ZkLoginService>(ZkLoginService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createSession', () => {
    it('should create a new authentication session', async () => {
      const mockSession = {
        ephemeralKeyPair: {
          keypair: {} as any,
          maxEpoch: 100,
          randomness: 'test-randomness',
        },
        nonce: 'test-nonce',
        provider: 'google' as any,
        maxEpoch: 100,
        userSalt: 'test-salt',
      };

      mockZkLoginService.createZkLoginSession.mockResolvedValue({
        authUrl: 'https://accounts.google.com/oauth/authorize?...',
        session: mockSession,
      });

      const result = await service.createSession('google');

      expect(result).toHaveProperty('sessionId');
      expect(result).toHaveProperty('authUrl');
      expect(result.authUrl).toContain('accounts.google.com');
      expect(mockZkLoginService.createZkLoginSession).toHaveBeenCalledWith('google');
    });

    it('should handle errors during session creation', async () => {
      mockZkLoginService.createZkLoginSession.mockRejectedValue(
        new Error('Failed to create session')
      );

      await expect(service.createSession('google')).rejects.toThrow(
        'Failed to create authentication session'
      );
    });
  });

  describe('completeAuthentication', () => {
    it('should complete authentication with valid session and code', async () => {
      const sessionId = 'test-session-id';
      const code = 'oauth-code';
      const jwt = 'mock-jwt-token';
      
      const mockUser = {
        zkLoginAddress: '0x1234567890abcdef',
        provider: 'google' as any,
        email: 'test@example.com',
        name: 'Test User',
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
      };

      // Create a session first
      const mockSession = {
        ephemeralKeyPair: {
          keypair: {} as any,
          maxEpoch: 100,
          randomness: 'test-randomness',
        },
        nonce: 'test-nonce',
        provider: 'google' as any,
        maxEpoch: 100,
        userSalt: 'test-salt',
      };

      mockZkLoginService.createZkLoginSession.mockResolvedValue({
        authUrl: 'https://accounts.google.com/oauth/authorize?...',
        session: mockSession,
      });

      const { sessionId: createdSessionId } = await service.createSession('google');

      // Mock the completion flow
      mockZkLoginService.exchangeCodeForToken.mockResolvedValue(jwt);
      mockZkLoginService.completeAuthentication.mockResolvedValue(mockUser);

      const result = await service.completeAuthentication(createdSessionId, code);

      expect(result).toHaveProperty('token');
      expect(result).toHaveProperty('user');
      expect(result.user.zkLoginAddress).toBe(mockUser.zkLoginAddress);
      expect(result.user.email).toBe(mockUser.email);
    });

    it('should handle invalid session ID', async () => {
      await expect(
        service.completeAuthentication('invalid-session-id', 'code')
      ).rejects.toThrow('Failed to complete authentication');
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token and return user', async () => {
      // Create a session and complete authentication first
      const mockSession = {
        ephemeralKeyPair: {
          keypair: {} as any,
          maxEpoch: 100,
          randomness: 'test-randomness',
        },
        nonce: 'test-nonce',
        provider: 'google' as any,
        maxEpoch: 100,
        userSalt: 'test-salt',
      };

      const mockUser = {
        zkLoginAddress: '0x1234567890abcdef',
        provider: 'google' as any,
        email: 'test@example.com',
        name: 'Test User',
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
      };

      mockZkLoginService.createZkLoginSession.mockResolvedValue({
        authUrl: 'https://accounts.google.com/oauth/authorize?...',
        session: mockSession,
      });

      mockZkLoginService.exchangeCodeForToken.mockResolvedValue('mock-jwt');
      mockZkLoginService.completeAuthentication.mockResolvedValue(mockUser);

      const { sessionId } = await service.createSession('google');
      const { token } = await service.completeAuthentication(sessionId, 'code');

      const verifiedUser = await service.verifyToken(token);

      expect(verifiedUser).toBeDefined();
      expect(verifiedUser?.zkLoginAddress).toBe(mockUser.zkLoginAddress);
    });

    it('should return null for invalid token', async () => {
      const result = await service.verifyToken('invalid-token');
      expect(result).toBeNull();
    });
  });

  describe('getUserZkLoginAddress', () => {
    it('should return zkLogin address for valid token', async () => {
      // Setup similar to verifyToken test
      const mockSession = {
        ephemeralKeyPair: {
          keypair: {} as any,
          maxEpoch: 100,
          randomness: 'test-randomness',
        },
        nonce: 'test-nonce',
        provider: 'google' as any,
        maxEpoch: 100,
        userSalt: 'test-salt',
      };

      const mockUser = {
        zkLoginAddress: '0x1234567890abcdef',
        provider: 'google' as any,
        email: 'test@example.com',
        name: 'Test User',
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
      };

      mockZkLoginService.createZkLoginSession.mockResolvedValue({
        authUrl: 'https://accounts.google.com/oauth/authorize?...',
        session: mockSession,
      });

      mockZkLoginService.exchangeCodeForToken.mockResolvedValue('mock-jwt');
      mockZkLoginService.completeAuthentication.mockResolvedValue(mockUser);

      const { sessionId } = await service.createSession('google');
      const { token } = await service.completeAuthentication(sessionId, 'code');

      const address = await service.getUserZkLoginAddress(token);

      expect(address).toBe(mockUser.zkLoginAddress);
    });

    it('should return null for invalid token', async () => {
      const address = await service.getUserZkLoginAddress('invalid-token');
      expect(address).toBeNull();
    });
  });
});
