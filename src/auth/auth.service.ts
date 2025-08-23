import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { sign, verify } from 'jsonwebtoken';
import { ZkLoginService, AuthenticatedUser, ZkLoginSession } from './zklogin.service';
import { defaultZkLoginConfig } from '../config/zklogin.config';
import { SuiService } from '../sui/sui.service';

export interface WalletUser {
  walletAddress: string;
  provider: 'wallet';
  name?: string;
}

export interface SessionToken {
  sessionId: string;
  address: string; // Can be zkLoginAddress or walletAddress
  provider: string;
  email?: string;
  name?: string;
  iat: number;
  exp: number;
}

export interface AuthSession {
  id: string;
  zkLoginSession?: ZkLoginSession;
  user?: AuthenticatedUser | WalletUser;
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
   * Authenticate with wallet
   */
  async authenticateWithWallet(walletAddress: string): Promise<{
    token: string;
    user: WalletUser;
  }> {
    try {
      this.logger.log(`Authenticating with wallet: ${walletAddress}`);
      
      // Create a wallet user
      const user: WalletUser = {
        walletAddress,
        provider: 'wallet',
        name: `Wallet (${walletAddress.substring(0, 6)}...${walletAddress.substring(walletAddress.length - 4)})`,
      };
      
      // Generate a simple token
      const token = `wallet_auth_${walletAddress}_${Date.now()}`;
      
      // Create a session for the wallet user
      const sessionId = this.generateSessionId();
      const authSession: AuthSession = {
        id: sessionId,
        user,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      };
      
      this.sessions.set(sessionId, authSession);
      
      return { token, user };
    } catch (error) {
      this.logger.error('Failed to authenticate with wallet', error);
      throw new Error('Failed to authenticate with wallet');
    }
  }

  /**
   * Create a new authentication session
   */
  async createSession(provider: string): Promise<{
    sessionId: string;
    authUrl: string;
  }> {
    try {
      // Generate session ID first
      // const sessionId = this.generateSessionId();
      
      // Create zkLogin session with sessionId as state
      // Generate session ID first
      const sessionId = this.generateSessionId();
      
      // Create zkLogin session with sessionId as state
      const { authUrl, session } = await this.zkLoginService.createZkLoginSession(
        provider as any,
         // Pass sessionId as state parameter
      );

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

      // Ensure zkLogin session exists
      const zkSession = session.zkLoginSession;
      if (!zkSession) {
        this.logger.error(`zkLogin session not found for session: ${sessionId}`);
        throw new Error('Invalid or expired session');
      }

      // Exchange code for JWT
      const jwt = await this.zkLoginService.exchangeCodeForToken(
        zkSession.provider,
        code
      );

      this.logger.log(`JWT obtained, completing zkLogin authentication...`);

      // Complete zkLogin authentication
      const user = await this.zkLoginService.completeAuthentication(
        zkSession,
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
  async verifyToken(token: string): Promise<AuthenticatedUser | WalletUser | null> {
    try {
      // Check if it's a wallet auth token
      if (token.startsWith('wallet_auth_')) {
        // Parse wallet address from token
        const parts = token.split('_');
        if (parts.length >= 3) {
          const walletAddress = parts[2];
          
          // For wallet auth, we don't need to check sessions
          // We just verify the token format is valid
          return {
            walletAddress,
            provider: 'wallet',
            name: `Wallet (${walletAddress.substring(0, 6)}...${walletAddress.substring(walletAddress.length - 4)})`,
          };
        }
        this.logger.error('Invalid wallet auth token format');
        return null;
      }
      
      // For zkLogin tokens, verify JWT
      try {
        const decoded = verify(token, this.config.jwt.secret) as SessionToken;

        // Get session
        const session = this.sessions.get(decoded.sessionId);
        if (!session || !session.user) {
          this.logger.error('Session not found or user not attached to session');
          return null;
        }

        if (session.expiresAt < new Date()) {
          this.logger.error('Session expired');
          this.sessions.delete(decoded.sessionId);
          return null;
        }

        return session.user;
      } catch (jwtError) {
        this.logger.error('JWT verification failed', jwtError);
        return null;
      }
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
      address: user.zkLoginAddress,
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
   * Get user's address for smart contract interactions
   */
  async getUserAddress(token: string): Promise<string | null> {
    const user = await this.verifyToken(token);
    if (!user) return null;
    
    // Handle both wallet and zkLogin users
    if ('walletAddress' in user) {
      return user.walletAddress;
    } else if ('zkLoginAddress' in user) {
      return user.zkLoginAddress;
    }
    
    return null;
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

      // Get the user's address (either wallet or zkLogin)
      const userAddress = 'walletAddress' in user ? user.walletAddress : user.zkLoginAddress;

      // Check authorization using the SuiCircle smart contract
      const isAuthorized = await this.suiService.isAuthorizedForFile(
        fileCid,
        userAddress
      );

      this.logger.log(
        `Authorization check for user ${userAddress} and file ${fileCid}: ${isAuthorized}`
      );

      return isAuthorized;
    } catch (error) {
      this.logger.error('Failed to check user authorization', error);
      return false;
    }
  }
}
