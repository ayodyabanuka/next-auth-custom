// Core types and interfaces
export * from './types';

// Utility classes
export { JWTUtil } from './jwt.util';
export { CookieUtil } from './cookie.util';

// Authentication service
export { AuthServiceImpl } from './auth.service';

// Re-export types for convenience
export type { AuthService } from './types';
export type { AuthMiddlewareOptions } from './middleware';

// Helper functions
export { createAuthMiddleware, getUserFromRequest } from './middleware';

// Auth client
export { AuthClient, createAuthClient } from './authClient';
export type {
  AuthClientConfig,
  AuthClientState,
  AuthClientListener,
} from './authClient';

// Factory function to create auth service
import { AuthServiceImpl } from './auth.service';
export function createAuthService(
  config: import('./types').AuthConfig,
  dbAdapter: import('./types').DatabaseAdapter
) {
  return new AuthServiceImpl(config, dbAdapter);
}

// Default configuration helper
export function createDefaultAuthConfig(
  overrides: Partial<import('./types').AuthConfig> = {}
): import('./types').AuthConfig {
  return {
    jwtSecret: process.env.JWT_SECRET || 'your-jwt-secret',
    jwtRefreshSecret:
      process.env.JWT_REFRESH_SECRET || 'your-jwt-refresh-secret',
    accessTokenExpiry: 15 * 60, // 15 minutes
    refreshTokenExpiry: 7 * 24 * 60 * 60, // 7 days
    cookieSecure: process.env.NODE_ENV === 'production',
    cookieSameSite: 'lax',
    enableTokenRotation: true,
    enableDeviceTracking: false,
    ...overrides,
  };
}
