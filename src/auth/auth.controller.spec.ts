import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { OAuthProvider } from '../config/zklogin.config';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;

  const mockAuthService = {
    createSession: jest.fn(),
    completeAuthentication: jest.fn(),
    verifyToken: jest.fn(),
    getSession: jest.fn(),
    revokeSession: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('initiateLogin', () => {
    it('should initiate login for Google provider', async () => {
      const mockSessionData = {
        sessionId: 'test-session-id',
        authUrl: 'https://accounts.google.com/oauth/authorize?...',
      };

      mockAuthService.createSession.mockResolvedValue(mockSessionData);

      const result = await controller.initiateLogin('google');

      expect(result).toEqual({
        success: true,
        data: {
          sessionId: 'test-session-id',
          authUrl: 'https://accounts.google.com/oauth/authorize?...',
          provider: 'google',
        },
      });

      expect(mockAuthService.createSession).toHaveBeenCalledWith('google');
    });

    it('should initiate login for Facebook provider', async () => {
      const mockSessionData = {
        sessionId: 'test-session-id',
        authUrl: 'https://www.facebook.com/v18.0/dialog/oauth?...',
      };

      mockAuthService.createSession.mockResolvedValue(mockSessionData);

      const result = await controller.initiateLogin('facebook');

      expect(result).toEqual({
        success: true,
        data: {
          sessionId: 'test-session-id',
          authUrl: 'https://www.facebook.com/v18.0/dialog/oauth?...',
          provider: 'facebook',
        },
      });

      expect(mockAuthService.createSession).toHaveBeenCalledWith('facebook');
    });

    it('should initiate login for Twitch provider', async () => {
      const mockSessionData = {
        sessionId: 'test-session-id',
        authUrl: 'https://id.twitch.tv/oauth2/authorize?...',
      };

      mockAuthService.createSession.mockResolvedValue(mockSessionData);

      const result = await controller.initiateLogin('twitch');

      expect(result).toEqual({
        success: true,
        data: {
          sessionId: 'test-session-id',
          authUrl: 'https://id.twitch.tv/oauth2/authorize?...',
          provider: 'twitch',
        },
      });

      expect(mockAuthService.createSession).toHaveBeenCalledWith('twitch');
    });

    it('should throw HttpException for unsupported provider', async () => {
      await expect(controller.initiateLogin('unsupported')).rejects.toThrow(
        new HttpException(
          'Unsupported OAuth provider: unsupported',
          HttpStatus.BAD_REQUEST
        )
      );

      expect(mockAuthService.createSession).not.toHaveBeenCalled();
    });

    it('should handle service errors', async () => {
      mockAuthService.createSession.mockRejectedValue(new Error('Service error'));

      await expect(controller.initiateLogin('google')).rejects.toThrow(
        new HttpException('Service error', HttpStatus.INTERNAL_SERVER_ERROR)
      );
    });

    it('should handle service errors without message', async () => {
      mockAuthService.createSession.mockRejectedValue(new Error());

      await expect(controller.initiateLogin('google')).rejects.toThrow(
        new HttpException('Failed to initiate login', HttpStatus.INTERNAL_SERVER_ERROR)
      );
    });
  });

  describe('handleCallback', () => {
    it('should handle successful OAuth callback', async () => {
      const callbackBody = {
        sessionId: 'test-session-id',
        code: 'oauth-authorization-code',
        state: 'optional-state',
      };

      const mockAuthResult = {
        token: 'jwt-session-token',
        user: {
          zkLoginAddress: '0x1234567890abcdef',
          provider: OAuthProvider.GOOGLE,
          email: 'test@example.com',
          name: 'Test User',
        },
      };

      mockAuthService.completeAuthentication.mockResolvedValue(mockAuthResult);

      const result = await controller.handleCallback(callbackBody);

      expect(result).toEqual({
        success: true,
        data: {
          token: 'jwt-session-token',
          user: {
            zkLoginAddress: '0x1234567890abcdef',
            provider: OAuthProvider.GOOGLE,
            email: 'test@example.com',
            name: 'Test User',
          },
        },
      });

      expect(mockAuthService.completeAuthentication).toHaveBeenCalledWith(
        'test-session-id',
        'oauth-authorization-code',
        'optional-state'
      );
    });

    it('should handle callback without state parameter', async () => {
      const callbackBody = {
        sessionId: 'test-session-id',
        code: 'oauth-authorization-code',
      };

      const mockAuthResult = {
        token: 'jwt-session-token',
        user: {
          zkLoginAddress: '0x1234567890abcdef',
          provider: OAuthProvider.GOOGLE,
          email: 'test@example.com',
          name: 'Test User',
        },
      };

      mockAuthService.completeAuthentication.mockResolvedValue(mockAuthResult);

      const result = await controller.handleCallback(callbackBody);

      expect(result.success).toBe(true);
      expect(mockAuthService.completeAuthentication).toHaveBeenCalledWith(
        'test-session-id',
        'oauth-authorization-code',
        undefined
      );
    });

    it('should handle authentication completion errors', async () => {
      const callbackBody = {
        sessionId: 'invalid-session-id',
        code: 'oauth-authorization-code',
      };

      mockAuthService.completeAuthentication.mockRejectedValue(
        new Error('Invalid or expired session')
      );

      await expect(controller.handleCallback(callbackBody)).rejects.toThrow(
        new HttpException('Invalid or expired session', HttpStatus.INTERNAL_SERVER_ERROR)
      );
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token and return user info', async () => {
      const authHeader = 'Bearer valid-jwt-token';
      const mockUser = {
        zkLoginAddress: '0x1234567890abcdef',
        provider: 'google',
        email: 'test@example.com',
        name: 'Test User',
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
      };

      mockAuthService.verifyToken.mockResolvedValue(mockUser);

      const result = await controller.verifyToken(authHeader);

      expect(result).toEqual({
        success: true,
        data: {
          user: mockUser,
          valid: true,
        },
      });

      expect(mockAuthService.verifyToken).toHaveBeenCalledWith('valid-jwt-token');
    });

    it('should handle invalid token', async () => {
      const authHeader = 'Bearer invalid-token';

      mockAuthService.verifyToken.mockResolvedValue(null);

      await expect(controller.verifyToken(authHeader)).rejects.toThrow(
        new HttpException('Invalid or expired token', HttpStatus.UNAUTHORIZED)
      );
    });

    it('should handle missing authorization header', async () => {
      await expect(controller.verifyToken('')).rejects.toThrow(
        new HttpException('Missing authorization header', HttpStatus.BAD_REQUEST)
      );
    });

    it('should handle malformed authorization header', async () => {
      const authHeader = 'InvalidFormat token';

      await expect(controller.verifyToken(authHeader)).rejects.toThrow(
        new HttpException('Invalid authorization header format', HttpStatus.BAD_REQUEST)
      );
    });

    it('should handle token verification errors', async () => {
      const authHeader = 'Bearer error-token';

      mockAuthService.verifyToken.mockRejectedValue(new Error('Token verification failed'));

      await expect(controller.verifyToken(authHeader)).rejects.toThrow(
        new HttpException('Token verification failed', HttpStatus.INTERNAL_SERVER_ERROR)
      );
    });
  });


});
