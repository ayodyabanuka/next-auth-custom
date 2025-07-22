import jwt from 'jsonwebtoken';
import { JWTPayload, User, AuthConfig } from './types';

export class JWTUtil {
  private config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
  }

  /**
   * Generate an access token for a user
   */
  generateAccessToken(user: User, deviceId?: string): string {
    const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
      userId: user.id,
      email: user.email,
      role: user.role,
      deviceId,
      type: 'access',
    };

    return jwt.sign(payload, this.config.jwtSecret, {
      expiresIn: this.config.accessTokenExpiry,
    });
  }

  /**
   * Generate a refresh token for a user
   */
  generateRefreshToken(user: User, deviceId?: string): string {
    const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
      userId: user.id,
      email: user.email,
      role: user.role,
      deviceId,
      type: 'refresh',
    };

    return jwt.sign(payload, this.config.jwtRefreshSecret, {
      expiresIn: this.config.refreshTokenExpiry,
    });
  }

  /**
   * Verify and decode an access token
   */
  verifyAccessToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(token, this.config.jwtSecret) as JWTPayload;

      if (decoded.type !== 'access') {
        return null;
      }

      return decoded;
    } catch (error) {
      return null;
    }
  }

  /**
   * Verify and decode a refresh token
   */
  verifyRefreshToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(
        token,
        this.config.jwtRefreshSecret
      ) as JWTPayload;

      if (decoded.type !== 'refresh') {
        return null;
      }

      return decoded;
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate both access and refresh tokens
   */
  generateTokenPair(
    user: User,
    deviceId?: string
  ): {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
  } {
    const accessToken = this.generateAccessToken(user, deviceId);
    const refreshToken = this.generateRefreshToken(user, deviceId);

    const accessTokenPayload = this.verifyAccessToken(accessToken);
    const expiresAt = accessTokenPayload?.exp || 0;

    return {
      accessToken,
      refreshToken,
      expiresAt,
    };
  }

  /**
   * Check if a token is expired
   */
  isTokenExpired(token: string, isRefreshToken = false): boolean {
    try {
      const decoded = isRefreshToken
        ? this.verifyRefreshToken(token)
        : this.verifyAccessToken(token);

      if (!decoded) return true;

      return Date.now() >= decoded.exp * 1000;
    } catch {
      return true;
    }
  }

  /**
   * Get token expiration time
   */
  getTokenExpiration(token: string, isRefreshToken = false): number | null {
    try {
      const decoded = isRefreshToken
        ? this.verifyRefreshToken(token)
        : this.verifyAccessToken(token);

      return decoded?.exp || null;
    } catch {
      return null;
    }
  }
}
