import bcrypt from 'bcryptjs';
import {
  AuthService,
  AuthResponse,
  LoginCredentials,
  RegisterData,
  User,
  DatabaseAdapter,
  AuthConfig,
} from './types';
import { JWTUtil } from './jwt.util';

export class AuthServiceImpl implements AuthService {
  private jwtUtil: JWTUtil;
  private dbAdapter: DatabaseAdapter;
  private config: AuthConfig;

  constructor(config: AuthConfig, dbAdapter: DatabaseAdapter) {
    this.config = config;
    this.dbAdapter = dbAdapter;
    this.jwtUtil = new JWTUtil(config);
  }

  /**
   * Register a new user
   */
  async register(data: RegisterData): Promise<AuthResponse> {
    try {
      // Check if user already exists
      const existingUser = await this.dbAdapter.findUserByEmail(data.email);
      if (existingUser) {
        return {
          success: false,
          error: 'User with this email already exists',
        };
      }

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(data.password, saltRounds);

      // Create user
      const user = await this.dbAdapter.createUser({
        email: data.email,
        name: data.name,
        role: data.role || 'user',
      });

      // Generate tokens
      const deviceId = this.config.enableDeviceTracking
        ? this.generateDeviceId()
        : undefined;
      const { accessToken, refreshToken, expiresAt } =
        this.jwtUtil.generateTokenPair(user, deviceId);

      // Store refresh token
      await this.dbAdapter.storeRefreshToken(user.id, refreshToken, deviceId);

      return {
        success: true,
        user,
        session: {
          user,
          accessToken,
          refreshToken,
          expiresAt,
          deviceId,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Registration failed',
      };
    }
  }

  /**
   * Login user with email and password
   */
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      // Find user by email
      const user = await this.dbAdapter.findUserByEmail(credentials.email);
      if (!user) {
        return {
          success: false,
          error: 'Invalid email or password',
        };
      }

      // Verify password (assuming password is stored in user object)
      // You'll need to implement password verification based on your database structure
      const isValidPassword = await this.verifyPassword(
        credentials.password,
        user
      );
      if (!isValidPassword) {
        return {
          success: false,
          error: 'Invalid email or password',
        };
      }

      // Generate tokens
      const deviceId =
        credentials.deviceId ||
        (this.config.enableDeviceTracking
          ? this.generateDeviceId()
          : undefined);
      const { accessToken, refreshToken, expiresAt } =
        this.jwtUtil.generateTokenPair(user, deviceId);

      // Store refresh token
      await this.dbAdapter.storeRefreshToken(user.id, refreshToken, deviceId);

      return {
        success: true,
        user,
        session: {
          user,
          accessToken,
          refreshToken,
          expiresAt,
          deviceId,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Login failed',
      };
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refresh(refreshToken: string): Promise<AuthResponse> {
    try {
      // Verify refresh token
      const payload = this.jwtUtil.verifyRefreshToken(refreshToken);
      if (!payload) {
        return {
          success: false,
          error: 'Invalid refresh token',
        };
      }

      // Check if token is expired
      if (this.jwtUtil.isTokenExpired(refreshToken, true)) {
        return {
          success: false,
          error: 'Refresh token expired',
        };
      }

      // Validate refresh token in database
      const isValid = await this.dbAdapter.validateRefreshToken(
        refreshToken,
        payload.userId
      );
      if (!isValid) {
        return {
          success: false,
          error: 'Invalid refresh token',
        };
      }

      // Get user
      const user = await this.dbAdapter.findUserById(payload.userId);
      if (!user) {
        return {
          success: false,
          error: 'User not found',
        };
      }

      // Generate new token pair
      const {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt,
      } = this.jwtUtil.generateTokenPair(user, payload.deviceId);

      // If token rotation is enabled, revoke old refresh token and store new one
      if (this.config.enableTokenRotation) {
        await this.dbAdapter.revokeRefreshToken(refreshToken, payload.userId);
        await this.dbAdapter.storeRefreshToken(
          user.id,
          newRefreshToken,
          payload.deviceId
        );
      }

      return {
        success: true,
        user,
        session: {
          user,
          accessToken: newAccessToken,
          refreshToken: this.config.enableTokenRotation
            ? newRefreshToken
            : refreshToken,
          expiresAt,
          deviceId: payload.deviceId,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Token refresh failed',
      };
    }
  }

  /**
   * Logout user by revoking refresh token
   */
  async logout(refreshToken: string): Promise<AuthResponse> {
    try {
      const payload = this.jwtUtil.verifyRefreshToken(refreshToken);
      if (payload) {
        await this.dbAdapter.revokeRefreshToken(refreshToken, payload.userId);
      }

      return {
        success: true,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Logout failed',
      };
    }
  }

  /**
   * Validate access token and return user
   */
  async validateAccessToken(token: string): Promise<User | null> {
    try {
      const payload = this.jwtUtil.verifyAccessToken(token);
      if (!payload) return null;

      if (this.jwtUtil.isTokenExpired(token)) {
        return null;
      }

      const user = await this.dbAdapter.findUserById(payload.userId);
      return user;
    } catch {
      return null;
    }
  }

  /**
   * Get user from access token
   */
  async getUserFromToken(token: string): Promise<User | null> {
    return this.validateAccessToken(token);
  }

  /**
   * Verify password against user data
   * This is a placeholder - implement based on your database structure
   */
  private async verifyPassword(password: string, user: User): Promise<boolean> {
    // This is a placeholder implementation
    // You need to implement this based on how passwords are stored in your database
    // For example, if you store hashed passwords in a separate field:
    // return bcrypt.compare(password, user.hashedPassword);

    // For now, returning false to indicate this needs to be implemented
    return false;
  }

  /**
   * Generate a unique device ID
   */
  private generateDeviceId(): string {
    return `device_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
