import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { sign, verify } from 'jsonwebtoken';
import { ZkLoginService, AuthenticatedUser, ZkLoginSession } from './zklogin.service';
import { defaultZkLoginConfig } from '../config/zklogin.config';
import { SuiService } from '../sui/sui.service';

export interface SessionToken {
  sessionId: string;
  zkLoginAddress: string;
  provider: string;
  email?: string;
  name?: string;
  iat: number;
  exp: number;
}

export interface AuthSession {
  id: string;
  zkLoginSession: ZkLoginSession;
  user?: AuthenticatedUser;
  createdAt: Date;
  expiresAt: Date;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly sessions = new Map<string, AuthSession>();
  private readonly config = defaultZkLoginConfig;

  constructor(
    private readonly zkLoginService: ZkLoginService,
    @Inject(forwardRef(() => SuiService))
    private readonly suiService: SuiService
  ) {}

  /**
   * Create a new authentication session
   */
  async createSession(provider: string): Promise<{
    sessionId: string;
    authUrl: string;
  }> {
    try {
      // Create zkLogin session
      const { authUrl, session } = await this.zkLoginService.createZkLoginSession(
        provider as any
      );

      // Generate session ID
      const sessionId = this.generateSessionId();

      // Store session
      const authSession: AuthSession = {
        id: sessionId,
        zkLoginSession: session,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      };

      this.sessions.set(sessionId, authSession);

      // Clean up expired sessions
      this.cleanupExpiredSessions();

      return { sessionId, authUrl };
    } catch (error) {
      this.logger.error('Failed to create authentication session', error);
      throw new Error('Failed to create authentication session');
    }
  }

  /**
   * Complete authentication with OAuth callback
   */
  async completeAuthentication(
    sessionId: string,
    code: string,
    state?: string
  ): Promise<{
    token: string;
    user: AuthenticatedUser;
  }> {
    try {
      this.logger.log(`Starting authentication completion for session: ${sessionId}`);

      // Get session
      const session = this.sessions.get(sessionId);
      if (!session) {
        this.logger.error(`Session not found: ${sessionId}`);
        throw new Error('Invalid or expired session');
      }

      if (session.expiresAt < new Date()) {
        this.logger.error(`Session expired: ${sessionId}`);
        this.sessions.delete(sessionId);
        throw new Error('Session expired');
      }

      this.logger.log(`Session found, exchanging code for JWT...`);

      // Exchange code for JWT
      const jwt = await this.zkLoginService.exchangeCodeForToken(
        session.zkLoginSession.provider,
        code
      );

      this.logger.log(`JWT obtained, completing zkLogin authentication...`);

      // Complete zkLogin authentication
      const user = await this.zkLoginService.completeAuthentication(
        session.zkLoginSession,
        jwt
      );

      this.logger.log(`zkLogin authentication completed for user: ${user.zkLoginAddress}`);

      // Update session with user info
      session.user = user;

      // Generate session token
      const token = this.generateSessionToken(sessionId, user);

      this.logger.log(`Session token generated successfully`);

      return { token, user };
    } catch (error) {
      this.logger.error('Failed to complete authentication', error);
      this.logger.error('Error stack:', error.stack);
      throw new Error('Failed to complete authentication');
    }
  }

  /**
   * Verify session token
   */
  async verifyToken(token: string): Promise<AuthenticatedUser | null> {
    try {
      // Verify JWT token
      const decoded = verify(token, this.config.jwt.secret) as SessionToken;

      // Get session
      const session = this.sessions.get(decoded.sessionId);
      if (!session || !session.user) {
        return null;
      }

      if (session.expiresAt < new Date()) {
        this.sessions.delete(decoded.sessionId);
        return null;
      }

      return session.user;
    } catch (error) {
      this.logger.error('Failed to verify token', error);
      return null;
    }
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): AuthSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Revoke session
   */
  revokeSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Generate session ID
   */
  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate session token
   */
  private generateSessionToken(sessionId: string, user: AuthenticatedUser): string {
    const payload: Omit<SessionToken, 'iat' | 'exp'> = {
      sessionId,
      zkLoginAddress: user.zkLoginAddress,
      provider: user.provider,
      email: user.email,
      name: user.name,
    };

    return sign(payload, this.config.jwt.secret, {
      expiresIn: this.config.jwt.expiresIn,
    } as any);
  }

  /**
   * Clean up expired sessions
   */
  private cleanupExpiredSessions(): void {
    const now = new Date();
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(sessionId);
      }
    }
  }

  /**
   * Get user's zkLogin address for smart contract interactions
   */
  async getUserZkLoginAddress(token: string): Promise<string | null> {
    const user = await this.verifyToken(token);
    return user?.zkLoginAddress || null;
  }

  /**
   * Check if user is authorized for a specific file
   * This integrates with the existing SuiCircle smart contract
   */
  async isUserAuthorizedForFile(
    token: string,
    fileCid: string
  ): Promise<boolean> {
    try {
      const user = await this.verifyToken(token);
      if (!user) {
        return false;
      }

      // Check authorization using the SuiCircle smart contract
      const isAuthorized = await this.suiService.isAuthorizedForFile(
        fileCid,
        user.zkLoginAddress
      );

      this.logger.log(
        `Authorization check for user ${user.zkLoginAddress} and file ${fileCid}: ${isAuthorized}`
      );

      return isAuthorized;
    } catch (error) {
      this.logger.error('Failed to check user authorization', error);
      return false;
    }
  }
}
