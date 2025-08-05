import {
  Controller,
  Get,
  Post,
  Query,
  Body,
  Param,
  Headers,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { OAuthProvider } from '../config/zklogin.config';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  /**
   * Initiate zkLogin authentication flow
   * GET /auth/login/:provider
   */
  @Get('login/:provider')
  async initiateLogin(@Param('provider') provider: string) {
    try {
      // Validate provider
      if (!Object.values(OAuthProvider).includes(provider as OAuthProvider)) {
        throw new HttpException(
          `Unsupported OAuth provider: ${provider}`,
          HttpStatus.BAD_REQUEST
        );
      }

      const { sessionId, authUrl } = await this.authService.createSession(provider);

      return {
        success: true,
        data: {
          sessionId,
          authUrl,
          provider,
        },
      };
    } catch (error) {
      this.logger.error('Failed to initiate login', error);
      throw new HttpException(
        error.message || 'Failed to initiate login',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Handle Google OAuth callback (GET request from Google)
   * GET /auth/google/callback
   */
  @Get('google/callback')
  async handleGoogleCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error?: string
  ) {
    return this.handleOAuthCallback('google', code, state, error);
  }

  /**
   * Handle Facebook OAuth callback (GET request from Facebook)
   * GET /auth/facebook/callback
   */
  @Get('facebook/callback')
  async handleFacebookCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error?: string
  ) {
    return this.handleOAuthCallback('facebook', code, state, error);
  }

  /**
   * Handle Twitch OAuth callback (GET request from Twitch)
   * GET /auth/twitch/callback
   */
  @Get('twitch/callback')
  async handleTwitchCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error?: string
  ) {
    return this.handleOAuthCallback('twitch', code, state, error);
  }

  /**
   * Handle GitHub OAuth callback (GET request from GitHub)
   * GET /auth/github/callback
   */
  @Get('github/callback')
  async handleGithubCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error?: string
  ) {
    return this.handleOAuthCallback('github', code, state, error);
  }

  /**
   * Generic OAuth callback handler
   */
  private async handleOAuthCallback(
    provider: string,
    code: string,
    state: string,
    error?: string
  ) {
    try {
      this.logger.log(`${provider} OAuth callback received: code=${code?.substring(0, 10)}..., state=${state}, error=${error}`);

      if (error) {
        this.logger.error(`OAuth error: ${error}`);
        return this.createOAuthResponseHTML('oauth_error', { error });
      }

      if (!code) {
        this.logger.error('Missing authorization code in OAuth callback');
        return this.createOAuthResponseHTML('oauth_error', { error: 'Missing authorization code' });
      }

      const sessionId = state;
      if (!sessionId) {
        this.logger.error('Missing session ID in state parameter');
        return this.createOAuthResponseHTML('oauth_error', { error: 'Missing session ID' });
      }

      this.logger.log('Attempting to complete authentication...');
      const { token, user } = await this.authService.completeAuthentication(
        sessionId,
        code,
        state
      );

      this.logger.log('Authentication completed successfully');

      return this.createOAuthResponseHTML('oauth_success', {
        token,
        user: {
          zkLoginAddress: user.zkLoginAddress,
          provider: user.provider,
          email: user.email,
          name: user.name,
        }
      });
    } catch (error) {
      this.logger.error(`Failed to handle ${provider} OAuth callback`, error);
      return this.createOAuthResponseHTML('oauth_error', {
        error: error.message || 'Authentication failed'
      });
    }
  }

  /**
   * Create HTML response for OAuth popup
   */
  private createOAuthResponseHTML(type: string, data: any): string {
    const messageData = type === 'oauth_success' ? { type, data } : { type, ...data };

    return `
      <html>
        <body>
          <script>
            window.opener.postMessage(${JSON.stringify(messageData)}, '*');
            window.close();
          </script>
        </body>
      </html>
    `;
  }

  /**
   * Handle OAuth callback
   * POST /auth/callback
   */
  @Post('callback')
  async handleCallback(
    @Body()
    body: {
      sessionId: string;
      code: string;
      state?: string;
    }
  ) {
    try {
      const { sessionId, code, state } = body;

      this.logger.log(`OAuth callback received: sessionId=${sessionId}, code=${code?.substring(0, 10)}..., state=${state}`);
      this.logger.log(`Full body received:`, JSON.stringify(body));

      if (!sessionId || !code) {
        this.logger.error('Missing required parameters in OAuth callback');
        throw new HttpException(
          'Missing required parameters: sessionId and code',
          HttpStatus.BAD_REQUEST
        );
      }

      // Check if session exists
      const session = this.authService.getSession(sessionId);
      if (!session) {
        this.logger.error(`Session not found: ${sessionId}`);
        throw new HttpException(
          'Invalid or expired session',
          HttpStatus.BAD_REQUEST
        );
      }
      this.logger.log(`Session found: ${sessionId}, provider: ${session.zkLoginSession.provider}`);

      this.logger.log('Attempting to complete authentication...');
      const { token, user } = await this.authService.completeAuthentication(
        sessionId,
        code,
        state
      );

      this.logger.log('Authentication completed successfully');
      this.logger.log(`User authenticated: ${user.zkLoginAddress}, provider: ${user.provider}`);

      return {
        success: true,
        data: {
          token,
          user: {
            zkLoginAddress: user.zkLoginAddress,
            provider: user.provider,
            email: user.email,
            name: user.name,
          },
        },
      };
    } catch (error) {
      this.logger.error('Failed to handle OAuth callback', error);
      this.logger.error('Error details:', error.stack);
      throw new HttpException(
        error.message || 'Failed to complete authentication',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Verify authentication token
   * GET /auth/verify
   */
  @Get('verify')
  async verifyToken(@Headers('authorization') authorization: string) {
    try {
      if (!authorization || !authorization.startsWith('Bearer ')) {
        throw new HttpException(
          'Missing or invalid authorization header',
          HttpStatus.UNAUTHORIZED
        );
      }

      const token = authorization.substring(7); // Remove 'Bearer ' prefix
      const user = await this.authService.verifyToken(token);

      if (!user) {
        throw new HttpException('Invalid or expired token', HttpStatus.UNAUTHORIZED);
      }

      return {
        success: true,
        data: {
          user: {
            zkLoginAddress: user.zkLoginAddress,
            provider: user.provider,
            email: user.email,
            name: user.name,
          },
        },
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to verify token', error);
      throw new HttpException(
        'Failed to verify token',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get user profile
   * GET /auth/profile
   */
  @Get('profile')
  async getProfile(@Headers('authorization') authorization: string) {
    try {
      if (!authorization || !authorization.startsWith('Bearer ')) {
        throw new HttpException(
          'Missing or invalid authorization header',
          HttpStatus.UNAUTHORIZED
        );
      }

      const token = authorization.substring(7);
      const user = await this.authService.verifyToken(token);

      if (!user) {
        throw new HttpException('Invalid or expired token', HttpStatus.UNAUTHORIZED);
      }

      return {
        success: true,
        data: {
          zkLoginAddress: user.zkLoginAddress,
          provider: user.provider,
          email: user.email,
          name: user.name,
          sub: user.sub,
          aud: user.aud,
          iss: user.iss,
        },
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      this.logger.error('Failed to get profile', error);
      throw new HttpException(
        'Failed to get profile',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Logout and revoke session
   * POST /auth/logout
   */
  @Post('logout')
  async logout(@Headers('authorization') authorization: string) {
    try {
      if (!authorization || !authorization.startsWith('Bearer ')) {
        throw new HttpException(
          'Missing or invalid authorization header',
          HttpStatus.UNAUTHORIZED
        );
      }

      const token = authorization.substring(7);
      
      // Extract session ID from token (this is a simplified approach)
      // In a real implementation, you might want to decode the JWT to get the session ID
      const user = await this.authService.verifyToken(token);
      
      if (user) {
        // For now, we'll just return success
        // In a full implementation, you'd revoke the specific session
        return {
          success: true,
          message: 'Logged out successfully',
        };
      }

      return {
        success: true,
        message: 'Already logged out',
      };
    } catch (error) {
      this.logger.error('Failed to logout', error);
      throw new HttpException(
        'Failed to logout',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Check file access authorization
   * GET /auth/check-access/:fileCid
   */
  @Get('check-access/:fileCid')
  async checkFileAccess(
    @Param('fileCid') fileCid: string,
    @Headers('authorization') authorization: string
  ) {
    try {
      if (!authorization || !authorization.startsWith('Bearer ')) {
        throw new HttpException(
          'Missing or invalid authorization header',
          HttpStatus.UNAUTHORIZED
        );
      }

      const token = authorization.substring(7);
      const isAuthorized = await this.authService.isUserAuthorizedForFile(
        token,
        fileCid
      );

      return {
        success: true,
        data: {
          fileCid,
          authorized: isAuthorized,
        },
      };
    } catch (error) {
      this.logger.error('Failed to check file access', error);
      throw new HttpException(
        'Failed to check file access',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}
