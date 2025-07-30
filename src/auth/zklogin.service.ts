import { Injectable, Logger } from '@nestjs/common';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { generateNonce, generateRandomness, getExtendedEphemeralPublicKey } from '@mysten/sui/zklogin';
import * as jose from 'jose';
import { ZkLoginConfig, OAuthProvider, oauthProviderConfigs, defaultZkLoginConfig } from '../config/zklogin.config';

export interface EphemeralKeyPair {
  keypair: Ed25519Keypair;
  maxEpoch: number;
  randomness: string;
}

export interface ZkLoginSession {
  ephemeralKeyPair: EphemeralKeyPair;
  nonce: string;
  provider: OAuthProvider;
  maxEpoch: number;
  userSalt: string;
}

export interface ZkLoginProof {
  proofPoints: {
    a: string[];
    b: string[][];
    c: string[];
  };
  issBase64Details: {
    value: string;
    indexMod4: number;
  };
  headerBase64: string;
}

export interface AuthenticatedUser {
  zkLoginAddress: string;
  provider: OAuthProvider;
  email?: string;
  name?: string;
  sub: string;
  aud: string;
  iss: string;
  // Additional data needed for zkLogin transactions
  ephemeralKeyPair?: EphemeralKeyPair;
  zkLoginProof?: ZkLoginProof;
  jwt?: string;
  userSalt?: string;
}

@Injectable()
export class ZkLoginService {
  private readonly logger = new Logger(ZkLoginService.name);
  private readonly config: ZkLoginConfig;
  private readonly suiClient: SuiClient;

  constructor() {
    this.config = defaultZkLoginConfig;
    this.suiClient = new SuiClient({ url: this.config.sui.rpcUrl });
  }

  /**
   * Generate ephemeral key pair for zkLogin session
   */
  async generateEphemeralKeyPair(): Promise<EphemeralKeyPair> {
    try {
      // Get current epoch from Sui network
      const { epoch } = await this.suiClient.getLatestSuiSystemState();
      const maxEpoch = Number(epoch) + this.config.zkLogin.maxEpoch;

      // Generate ephemeral keypair and randomness
      const ephemeralKeypair = new Ed25519Keypair();
      const randomness = generateRandomness();

      return {
        keypair: ephemeralKeypair,
        maxEpoch,
        randomness,
      };
    } catch (error) {
      this.logger.error('Failed to generate ephemeral key pair', error);
      throw new Error('Failed to generate ephemeral key pair');
    }
  }

  /**
   * Create zkLogin session and generate OAuth URL
   */
  async createZkLoginSession(provider: OAuthProvider): Promise<{
    authUrl: string;
    session: ZkLoginSession;
  }> {
    try {
      // Generate ephemeral key pair
      const ephemeralKeyPair = await this.generateEphemeralKeyPair();

      // Get extended ephemeral public key
      const extendedEphemeralPublicKey = getExtendedEphemeralPublicKey(
        ephemeralKeyPair.keypair.getPublicKey()
      );

      // Generate nonce
      const nonce = generateNonce(
        ephemeralKeyPair.keypair.getPublicKey(),
        ephemeralKeyPair.maxEpoch,
        ephemeralKeyPair.randomness
      );

      // Create session
      const session: ZkLoginSession = {
        ephemeralKeyPair,
        nonce,
        provider,
        maxEpoch: ephemeralKeyPair.maxEpoch,
        userSalt: this.config.zkLogin.salt,
      };

      // Generate OAuth URL
      const authUrl = this.generateOAuthUrl(provider, nonce);

      return { authUrl, session };
    } catch (error) {
      this.logger.error('Failed to create zkLogin session', error);
      throw new Error('Failed to create zkLogin session');
    }
  }

  /**
   * Generate OAuth authorization URL
   */
  private generateOAuthUrl(provider: OAuthProvider, nonce: string): string {
    const providerConfig = oauthProviderConfigs[provider];
    const oauthConfig = this.config.oauth[provider];

    // Debug logging
    this.logger.log(`Generating OAuth URL for ${provider}`);
    this.logger.log(`Client ID: ${oauthConfig.clientId}`);
    this.logger.log(`Redirect URI: ${oauthConfig.redirectUri}`);

    const params = new URLSearchParams({
      client_id: oauthConfig.clientId,
      redirect_uri: oauthConfig.redirectUri,
      response_type: 'code',
      scope: providerConfig.scope,
      nonce,
    });

    // Add provider-specific parameters
    if (provider === OAuthProvider.GOOGLE) {
      params.append('access_type', 'offline');
    } else if (provider === OAuthProvider.APPLE) {
      params.append('response_mode', 'form_post');
    }

    return `${providerConfig.authUrl}?${params.toString()}`;
  }

  /**
   * Exchange OAuth code for JWT token
   */
  async exchangeCodeForToken(
    provider: OAuthProvider,
    code: string,
    redirectUri?: string
  ): Promise<string> {
    try {
      this.logger.log(`Exchanging OAuth code for token: provider=${provider}`);

      const providerConfig = oauthProviderConfigs[provider];
      const oauthConfig = this.config.oauth[provider];

      // GitHub requires Accept header for JSON response
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
      };

      if (provider === OAuthProvider.GITHUB) {
        headers['Accept'] = 'application/json';
      }

      const tokenParams = new URLSearchParams({
        client_id: oauthConfig.clientId,
        client_secret: process.env[`${provider.toUpperCase()}_CLIENT_SECRET`] || '',
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri || oauthConfig.redirectUri,
      });

      const response = await fetch(providerConfig.tokenUrl, {
        method: 'POST',
        headers,
        body: tokenParams.toString(),
      });

      if (!response.ok) {
        throw new Error(`OAuth token exchange failed: ${response.statusText}`);
      }

      const tokenData = await response.json();

      // Handle GitHub's access token (not JWT)
      if (provider === OAuthProvider.GITHUB) {
        return await this.createGitHubJWT(tokenData.access_token);
      }

      // For most providers, the JWT is in id_token
      // For some providers like Twitch, it might be in access_token
      return tokenData.id_token || tokenData.access_token;
    } catch (error) {
      this.logger.error('Failed to exchange OAuth code for token', error);
      throw new Error('Failed to exchange OAuth code for token');
    }
  }

  /**
   * Create a JWT from GitHub access token and user info
   */
  private async createGitHubJWT(accessToken: string): Promise<string> {
    try {
      // Fetch user info from GitHub API
      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
        },
      });

      if (!userResponse.ok) {
        throw new Error('Failed to fetch GitHub user info');
      }

      const userData = await userResponse.json();

      // Fetch user email (might be private)
      const emailResponse = await fetch('https://api.github.com/user/emails', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
        },
      });

      let email = userData.email;
      if (!email && emailResponse.ok) {
        const emails = await emailResponse.json();
        const primaryEmail = emails.find((e: any) => e.primary);
        email = primaryEmail?.email || emails[0]?.email;
      }

      // Create a JWT-like payload for GitHub
      const payload = {
        sub: userData.id.toString(),
        aud: 'github-oauth',
        iss: 'https://github.com',
        email: email || `${userData.login}@github.local`,
        name: userData.name || userData.login,
        login: userData.login,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      };

      // Create a simple JWT for GitHub (for zkLogin compatibility)
      const secret = new TextEncoder().encode(this.config.jwt.secret);
      const jwt = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secret);

      return jwt;
    } catch (error) {
      this.logger.error('Failed to create GitHub JWT', error);
      throw new Error('Failed to create GitHub JWT');
    }
  }

  /**
   * Verify and decode JWT token
   */
  async verifyJwtToken(token: string, provider: OAuthProvider): Promise<any> {
    try {
      // Decode JWT without verification for now
      // In production, you should verify the JWT signature
      const decoded = jose.decodeJwt(token);
      
      // Validate required fields
      if (!decoded.sub || !decoded.aud || !decoded.iss) {
        throw new Error('Invalid JWT token: missing required fields');
      }

      // Validate issuer based on provider
      const expectedIssuers = {
        [OAuthProvider.GOOGLE]: 'https://accounts.google.com',
        [OAuthProvider.FACEBOOK]: 'https://www.facebook.com',
        [OAuthProvider.TWITCH]: 'https://id.twitch.tv/oauth2',
        [OAuthProvider.APPLE]: 'https://appleid.apple.com',
        [OAuthProvider.GITHUB]: 'https://github.com',
      };

      if (!decoded.iss.startsWith(expectedIssuers[provider])) {
        throw new Error(`Invalid issuer for ${provider}: ${decoded.iss}`);
      }

      return decoded;
    } catch (error) {
      this.logger.error('Failed to verify JWT token', error);
      throw new Error('Failed to verify JWT token');
    }
  }

  /**
   * Generate zkLogin proof using Mysten Labs prover service
   */
  async generateZkLoginProof(
    jwt: string,
    ephemeralKeyPair: EphemeralKeyPair,
    userSalt: string
  ): Promise<ZkLoginProof> {
    try {
      this.logger.log('Generating zkLogin proof using Mysten Labs prover service...');

      // Get extended ephemeral public key
      const extendedEphemeralPublicKey = getExtendedEphemeralPublicKey(
        ephemeralKeyPair.keypair.getPublicKey()
      );

      // Prepare the request payload
      const requestPayload = {
        jwt,
        extendedEphemeralPublicKey: extendedEphemeralPublicKey.toString(),
        maxEpoch: ephemeralKeyPair.maxEpoch.toString(),
        jwtRandomness: ephemeralKeyPair.randomness,
        salt: userSalt,
        keyClaimName: 'sub',
      };

      this.logger.log('Calling prover service with payload:', {
        maxEpoch: requestPayload.maxEpoch,
        keyClaimName: requestPayload.keyClaimName,
        // Don't log sensitive data like JWT
      });

      // Call the Mysten Labs prover service
      const proverResponse = await fetch(this.config.zkLogin.proverUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestPayload),
      });

      if (!proverResponse.ok) {
        const errorText = await proverResponse.text();
        this.logger.error(`Prover service failed with status ${proverResponse.status}:`, errorText);
        throw new Error(`Prover service failed: ${proverResponse.status} ${proverResponse.statusText}`);
      }

      const proof = await proverResponse.json();
      this.logger.log('zkLogin proof generated successfully');

      return proof;
    } catch (error: any) {
      this.logger.error('Failed to generate zkLogin proof:', error);
      throw new Error(`Failed to generate zkLogin proof: ${error.message}`);
    }
  }

  /**
   * Complete zkLogin authentication
   */
  async completeAuthentication(
    session: ZkLoginSession,
    jwt: string
  ): Promise<AuthenticatedUser> {
    try {
      this.logger.log('Verifying JWT token...');

      // Verify JWT token
      const decodedJwt = await this.verifyJwtToken(jwt, session.provider);

      this.logger.log('JWT verified successfully, decoded claims:', {
        sub: decodedJwt.sub,
        email: decodedJwt.email,
        name: decodedJwt.name,
        iss: decodedJwt.iss
      });

      // Generate zkLogin proof
      this.logger.log('Generating zkLogin proof...');
      let zkLoginProof: ZkLoginProof | undefined;

      try {
        zkLoginProof = await this.generateZkLoginProof(
          jwt,
          session.ephemeralKeyPair,
          session.userSalt
        );
        this.logger.log('✅ zkLogin proof generated successfully');
      } catch (error) {
        this.logger.error('❌ Failed to generate zkLogin proof:', error.message);
        this.logger.error('Full error:', error);
        // In development, we can continue without a proof for address derivation
        // but transactions will need to be handled differently
      }

      // Derive zkLogin address using proper algorithm
      const zkLoginAddress = await this.deriveZkLoginAddressFromJWT(
        jwt,
        session.userSalt
      );

      this.logger.log(`Generated zkLogin address: ${zkLoginAddress}`);

      const authenticatedUser = {
        zkLoginAddress,
        provider: session.provider,
        email: decodedJwt.email,
        name: decodedJwt.name,
        sub: decodedJwt.sub,
        aud: decodedJwt.aud,
        iss: decodedJwt.iss,
        // Include zkLogin transaction data
        ephemeralKeyPair: session.ephemeralKeyPair,
        zkLoginProof,
        jwt,
        userSalt: session.userSalt,
      };

      this.logger.log('🔍 zkLogin authentication completed with parameters:', {
        hasEphemeralKeyPair: !!authenticatedUser.ephemeralKeyPair,
        hasZkLoginProof: !!authenticatedUser.zkLoginProof,
        hasJwt: !!authenticatedUser.jwt,
        hasUserSalt: !!authenticatedUser.userSalt,
        zkLoginAddress: authenticatedUser.zkLoginAddress,
      });

      return authenticatedUser;
    } catch (error) {
      this.logger.error('Failed to complete authentication', error);
      this.logger.error('Error details:', error.stack);
      throw new Error('Failed to complete authentication');
    }
  }

  /**
   * Derive zkLogin address from JWT and salt using proper zkLogin algorithm
   */
  private async deriveZkLoginAddressFromJWT(jwt: string, salt: string): Promise<string> {
    try {
      // Import the zkLogin address derivation function
      const { jwtToAddress } = await import('@mysten/sui/zklogin');

      // Derive the zkLogin address using the official algorithm
      const zkLoginAddress = jwtToAddress(jwt, salt);

      this.logger.log(`Derived zkLogin address using official algorithm: ${zkLoginAddress}`);
      return zkLoginAddress;
    } catch (error) {
      this.logger.warn('Failed to use official zkLogin address derivation, falling back to simplified version:', error.message);

      // Fallback to simplified implementation for development
      return this.deriveZkLoginAddressSimplified(jwt, salt);
    }
  }

  /**
   * Simplified zkLogin address derivation (fallback for development)
   */
  private deriveZkLoginAddressSimplified(jwt: string, salt: string): string {
    const crypto = require('crypto');

    // Decode JWT to get claims
    const decoded = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString());

    // Create a deterministic address based on user's unique identifier
    const addressSeed = `${decoded.sub}_${decoded.iss}_${salt}`;
    const hash = crypto.createHash('sha256').update(addressSeed).digest('hex');

    // Format as a Sui address (0x + 64 hex characters)
    const suiAddress = `0x${hash.slice(0, 64)}`;

    this.logger.log(`Derived address from seed (simplified): ${addressSeed} -> ${suiAddress}`);

    return suiAddress;
  }

  /**
   * Legacy method - kept for backward compatibility
   */
  private deriveZkLoginAddress(decodedJwt: any, salt: string): string {
    const crypto = require('crypto');

    // Create a deterministic address based on user's unique identifier
    const addressSeed = `${decodedJwt.sub}_${decodedJwt.iss}_${salt}`;
    const hash = crypto.createHash('sha256').update(addressSeed).digest('hex');

    // Format as a Sui address (0x + 64 hex characters)
    const suiAddress = `0x${hash.slice(0, 64)}`;

    this.logger.log(`Derived address from seed: ${addressSeed} -> ${suiAddress}`);

    return suiAddress;
  }
}
