import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard, AuthenticatedRequest } from './auth.guard';
import { AuthService } from './auth.service';

describe('AuthGuard', () => {
  let guard: AuthGuard;
  let authService: AuthService;

  const mockAuthService = {
    verifyToken: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    guard = module.get<AuthGuard>(AuthGuard);
    authService = module.get<AuthService>(AuthService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    let mockExecutionContext: ExecutionContext;
    let mockRequest: AuthenticatedRequest;

    beforeEach(() => {
      mockRequest = {
        headers: {},
      } as AuthenticatedRequest;

      mockExecutionContext = {
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      } as ExecutionContext;
    });

    it('should allow access with valid Bearer token', async () => {
      const mockUser = {
        zkLoginAddress: '0x1234567890abcdef',
        provider: 'google',
        email: 'test@example.com',
        name: 'Test User',
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
      };

      mockRequest.headers.authorization = 'Bearer valid-token';
      mockAuthService.verifyToken.mockResolvedValue(mockUser);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect(mockRequest.user).toEqual(mockUser);
      expect(mockAuthService.verifyToken).toHaveBeenCalledWith('valid-token');
    });

    it('should throw UnauthorizedException when no authorization header', async () => {
      // No authorization header
      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(mockAuthService.verifyToken).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when authorization header is malformed', async () => {
      mockRequest.headers.authorization = 'InvalidFormat token';

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(mockAuthService.verifyToken).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when authorization header has no token', async () => {
      mockRequest.headers.authorization = 'Bearer';

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(mockAuthService.verifyToken).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when token verification returns null', async () => {
      mockRequest.headers.authorization = 'Bearer invalid-token';
      mockAuthService.verifyToken.mockResolvedValue(null);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid or expired token')
      );

      expect(mockAuthService.verifyToken).toHaveBeenCalledWith('invalid-token');
    });

    it('should throw UnauthorizedException when token verification throws error', async () => {
      mockRequest.headers.authorization = 'Bearer error-token';
      mockAuthService.verifyToken.mockRejectedValue(new Error('Token verification failed'));

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Authentication failed')
      );

      expect(mockAuthService.verifyToken).toHaveBeenCalledWith('error-token');
    });

    it('should handle different Bearer token formats', async () => {
      const mockUser = {
        zkLoginAddress: '0x1234567890abcdef',
        provider: 'google',
        email: 'test@example.com',
        name: 'Test User',
        sub: 'google-user-id',
        aud: 'client-id',
        iss: 'https://accounts.google.com',
      };

      // Test with extra spaces
      mockRequest.headers.authorization = '  Bearer   valid-token  ';
      mockAuthService.verifyToken.mockResolvedValue(mockUser);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect(mockRequest.user).toEqual(mockUser);
      expect(mockAuthService.verifyToken).toHaveBeenCalledWith('valid-token');
    });

    it('should not accept non-Bearer token types', async () => {
      mockRequest.headers.authorization = 'Basic dXNlcjpwYXNz';

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(mockAuthService.verifyToken).not.toHaveBeenCalled();
    });

    it('should handle case-sensitive Bearer token type', async () => {
      mockRequest.headers.authorization = 'bearer valid-token';

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(mockAuthService.verifyToken).not.toHaveBeenCalled();
    });
  });

  describe('extractTokenFromHeader', () => {
    it('should extract token from valid Bearer authorization header', () => {
      const mockRequest = {
        headers: {
          authorization: 'Bearer valid-token-123',
        },
      } as any;

      const token = (guard as any).extractTokenFromHeader(mockRequest);

      expect(token).toBe('valid-token-123');
    });

    it('should return undefined for missing authorization header', () => {
      const mockRequest = {
        headers: {},
      } as any;

      const token = (guard as any).extractTokenFromHeader(mockRequest);

      expect(token).toBeUndefined();
    });

    it('should return undefined for non-Bearer authorization header', () => {
      const mockRequest = {
        headers: {
          authorization: 'Basic dXNlcjpwYXNz',
        },
      } as any;

      const token = (guard as any).extractTokenFromHeader(mockRequest);

      expect(token).toBeUndefined();
    });

    it('should return undefined for malformed Bearer header', () => {
      const mockRequest = {
        headers: {
          authorization: 'Bearer',
        },
      } as any;

      const token = (guard as any).extractTokenFromHeader(mockRequest);

      expect(token).toBeUndefined();
    });

    it('should handle authorization header with multiple spaces', () => {
      const mockRequest = {
        headers: {
          authorization: 'Bearer   token-with-spaces   ',
        },
      } as any;

      const token = (guard as any).extractTokenFromHeader(mockRequest);

      expect(token).toBe('token-with-spaces');
    });
  });
});
