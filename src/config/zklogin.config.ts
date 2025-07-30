/**
 * zkLogin Configuration
 * 
 * This file contains configuration settings for zkLogin integration,
 * including OAuth provider settings, salt generation, and Sui network configuration.
 */

export interface ZkLoginConfig {
  // OAuth Provider Settings
  oauth: {
    google: {
      clientId: string;
      redirectUri: string;
    };
    facebook: {
      clientId: string;
      redirectUri: string;
    };
    twitch: {
      clientId: string;
      redirectUri: string;
    };
    apple: {
      clientId: string;
      redirectUri: string;
    };
    github: {
      clientId: string;
      redirectUri: string;
    };
  };
  
  // Sui Network Configuration
  sui: {
    network: 'testnet' | 'mainnet' | 'devnet';
    rpcUrl: string;
    packageId?: string; // SuiCircle package ID
    registryId?: string; // SuiCircle registry object ID
  };
  
  // zkLogin Specific Settings
  zkLogin: {
    // Salt for address derivation (should be unique per application)
    salt: string;
    // Maximum epoch for ephemeral key pairs
    maxEpoch: number;
    // Prover service URL for generating zkLogin proofs
    proverUrl: string;
  };
  
  // JWT Settings
  jwt: {
    // Secret for signing session tokens
    secret: string;
    // Token expiration time
    expiresIn: string;
  };
}

/**
 * Default zkLogin configuration
 * Environment variables should override these defaults
 */
export const defaultZkLoginConfig: ZkLoginConfig = {
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback',
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID || '',
      redirectUri: process.env.FACEBOOK_REDIRECT_URI || 'http://localhost:3000/auth/facebook/callback',
    },
    twitch: {
      clientId: process.env.TWITCH_CLIENT_ID || '',
      redirectUri: process.env.TWITCH_REDIRECT_URI || 'http://localhost:3000/auth/twitch/callback',
    },
    apple: {
      clientId: process.env.APPLE_CLIENT_ID || '',
      redirectUri: process.env.APPLE_REDIRECT_URI || 'http://localhost:3000/auth/apple/callback',
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID || '',
      redirectUri: process.env.GITHUB_REDIRECT_URI || 'http://localhost:5173/',
    },
  },
  
  sui: {
    network: (process.env.SUI_NETWORK as 'testnet' | 'mainnet' | 'devnet') || 'testnet',
    rpcUrl: process.env.SUI_RPC_URL || 'https://fullnode.testnet.sui.io:443',
    packageId: process.env.SUICIRCLE_PACKAGE_ID,
    registryId: process.env.SUICIRCLE_REGISTRY_ID,
  },
  
  zkLogin: {
    salt: process.env.ZKLOGIN_SALT || 'default-salt-change-in-production',
    maxEpoch: parseInt(process.env.ZKLOGIN_MAX_EPOCH || '10'),
    proverUrl: process.env.ZKLOGIN_PROVER_URL || 'https://prover-dev.mystenlabs.com/v1',
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'your-jwt-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
  },
};

// Debug logging for environment variables
console.log('=== zkLogin Config Debug ===');
console.log('GITHUB_CLIENT_ID:', process.env.GITHUB_CLIENT_ID);
console.log('GITHUB_REDIRECT_URI:', process.env.GITHUB_REDIRECT_URI);
console.log('GitHub config:', defaultZkLoginConfig.oauth.github);
console.log('===========================');

/**
 * Supported OAuth providers for zkLogin
 */
export enum OAuthProvider {
  GOOGLE = 'google',
  FACEBOOK = 'facebook',
  TWITCH = 'twitch',
  APPLE = 'apple',
  GITHUB = 'github',
}

/**
 * OAuth provider configurations
 */
export const oauthProviderConfigs = {
  [OAuthProvider.GOOGLE]: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scope: 'openid email profile',
  },
  [OAuthProvider.FACEBOOK]: {
    authUrl: 'https://www.facebook.com/v18.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v18.0/oauth/access_token',
    userInfoUrl: 'https://graph.facebook.com/me',
    scope: 'email',
  },
  [OAuthProvider.TWITCH]: {
    authUrl: 'https://id.twitch.tv/oauth2/authorize',
    tokenUrl: 'https://id.twitch.tv/oauth2/token',
    userInfoUrl: 'https://api.twitch.tv/helix/users',
    scope: 'openid user:read:email',
  },
  [OAuthProvider.APPLE]: {
    authUrl: 'https://appleid.apple.com/auth/authorize',
    tokenUrl: 'https://appleid.apple.com/auth/token',
    userInfoUrl: '', // Apple doesn't provide a userinfo endpoint
    scope: 'name email',
  },
  [OAuthProvider.GITHUB]: {
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scope: 'user:email',
  },
};

/**
 * Validate zkLogin configuration
 */
export function validateZkLoginConfig(config: ZkLoginConfig): void {
  const errors: string[] = [];
  
  // Validate OAuth configurations
  Object.entries(config.oauth).forEach(([provider, settings]) => {
    if (!settings.clientId) {
      errors.push(`Missing client ID for ${provider}`);
    }
    if (!settings.redirectUri) {
      errors.push(`Missing redirect URI for ${provider}`);
    }
  });
  
  // Validate Sui configuration
  if (!config.sui.rpcUrl) {
    errors.push('Missing Sui RPC URL');
  }
  
  // Validate zkLogin configuration
  if (!config.zkLogin.salt) {
    errors.push('Missing zkLogin salt');
  }
  
  if (config.zkLogin.salt === 'default-salt-change-in-production') {
    console.warn('WARNING: Using default salt in production is not secure!');
  }
  
  // Validate JWT configuration
  if (!config.jwt.secret) {
    errors.push('Missing JWT secret');
  }
  
  if (config.jwt.secret === 'your-jwt-secret-change-in-production') {
    console.warn('WARNING: Using default JWT secret in production is not secure!');
  }
  
  if (errors.length > 0) {
    throw new Error(`zkLogin configuration errors: ${errors.join(', ')}`);
  }
}
