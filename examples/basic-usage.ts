/**
 * Basic Usage Example for @abdev/next-auth-custom
 *
 * This example shows how to set up the authentication system
 * with a simple in-memory database adapter.
 */

import {
  createAuthService,
  createDefaultAuthConfig,
  DatabaseAdapter,
  User,
  AuthConfig,
} from '@ayodyabanuka/next-auth-custom';

// Example in-memory database adapter
class InMemoryDatabaseAdapter implements DatabaseAdapter {
  private users: Map<string, User> = new Map();
  private refreshTokens: Map<
    string,
    { userId: string; deviceId?: string; revoked: boolean }
  > = new Map();

  async findUserByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    return null;
  }

  async findUserById(id: string): Promise<User | null> {
    return this.users.get(id) || null;
  }

  async createUser(
    data: Omit<User, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<User> {
    const id = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const user: User = {
      id,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.set(id, user);
    return user;
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    const user = this.users.get(id);
    if (!user) {
      throw new Error('User not found');
    }
    const updatedUser = { ...user, ...data, updatedAt: new Date() };
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  async storeRefreshToken(
    userId: string,
    token: string,
    deviceId?: string
  ): Promise<void> {
    this.refreshTokens.set(token, { userId, deviceId, revoked: false });
  }

  async validateRefreshToken(token: string, userId: string): Promise<boolean> {
    const stored = this.refreshTokens.get(token);
    return stored ? stored.userId === userId && !stored.revoked : false;
  }

  async revokeRefreshToken(token: string, userId: string): Promise<void> {
    const stored = this.refreshTokens.get(token);
    if (stored && stored.userId === userId) {
      stored.revoked = true;
    }
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    for (const [token, stored] of this.refreshTokens.entries()) {
      if (stored.userId === userId) {
        stored.revoked = true;
      }
    }
  }
}

// Configuration
const authConfig: AuthConfig = createDefaultAuthConfig({
  jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
  jwtRefreshSecret:
    process.env.JWT_REFRESH_SECRET || 'your-super-secret-refresh-key',
  accessTokenExpiry: 15 * 60, // 15 minutes
  refreshTokenExpiry: 7 * 24 * 60 * 60, // 7 days
  enableTokenRotation: true,
  enableDeviceTracking: false,
});

// Create database adapter and auth service
const dbAdapter = new InMemoryDatabaseAdapter();
const authService = createAuthService(authConfig, dbAdapter);

// Example usage functions
export async function exampleRegister(
  email: string,
  password: string,
  name?: string
) {
  const result = await authService.register({ email, password, name });

  if (result.success) {
    console.log('Registration successful:', result.user);
    return result.session;
  } else {
    console.error('Registration failed:', result.error);
    return null;
  }
}

export async function exampleLogin(email: string, password: string) {
  const result = await authService.login({ email, password });

  if (result.success) {
    console.log('Login successful:', result.user);
    return result.session;
  } else {
    console.error('Login failed:', result.error);
    return null;
  }
}

export async function exampleRefresh(refreshToken: string) {
  const result = await authService.refresh(refreshToken);

  if (result.success) {
    console.log('Token refresh successful');
    return result.session;
  } else {
    console.error('Token refresh failed:', result.error);
    return null;
  }
}

export async function exampleLogout(refreshToken: string) {
  const result = await authService.logout(refreshToken);

  if (result.success) {
    console.log('Logout successful');
  } else {
    console.error('Logout failed:', result.error);
  }
}

export async function exampleValidateToken(accessToken: string) {
  const user = await authService.validateAccessToken(accessToken);

  if (user) {
    console.log('Token is valid, user:', user);
    return user;
  } else {
    console.log('Token is invalid or expired');
    return null;
  }
}

// Example usage
async function runExample() {
  console.log('=== Authentication Example ===\n');

  // Register a new user
  console.log('1. Registering user...');
  const registerSession = await exampleRegister(
    'john@example.com',
    'password123',
    'John Doe'
  );

  if (!registerSession) {
    console.log('Registration failed, stopping example');
    return;
  }

  // Login with the same user
  console.log('\n2. Logging in...');
  const loginSession = await exampleLogin('john@example.com', 'password123');

  if (!loginSession) {
    console.log('Login failed, stopping example');
    return;
  }

  // Validate access token
  console.log('\n3. Validating access token...');
  const user = await exampleValidateToken(loginSession.accessToken);

  if (!user) {
    console.log('Token validation failed');
    return;
  }

  // Refresh token
  console.log('\n4. Refreshing token...');
  const refreshSession = await exampleRefresh(loginSession.refreshToken);

  if (!refreshSession) {
    console.log('Token refresh failed');
    return;
  }

  // Logout
  console.log('\n5. Logging out...');
  await exampleLogout(refreshSession.refreshToken);

  console.log('\n=== Example completed ===');
}

// Uncomment to run the example
// runExample().catch(console.error);
