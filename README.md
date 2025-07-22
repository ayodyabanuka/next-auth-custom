# @ayodyabanuka/next-auth-custom

A comprehensive helper library for custom JWT-based authentication in Next.js 13/14+ (App Router) without Firebase Auth.

## Features

- 🔐 **Custom JWT Authentication** - Full control over your authentication flow
- 🔄 **Token Rotation** - Secure refresh token rotation (optional)
- 🍪 **HttpOnly Cookies** - Secure token storage in cookies
- 🛡️ **Route Protection** - Middleware for protecting routes
- 📱 **Device Tracking** - Optional device-based session management
- 🔧 **Database Agnostic** - Works with any database (Firestore, PostgreSQL, etc.)
- ⚡ **SSR Compatible** - Fully compatible with Next.js App Router
- 📦 **TypeScript** - Full TypeScript support with comprehensive types

## Installation

```bash
npm install @abdev/next-auth-custom
```

## Quick Example

```typescript
import {
  createAuthService,
  createDefaultAuthConfig,
  JWTUtil,
  CookieUtil,
} from '@abdev/next-auth-custom';

// Create configuration
const config = createDefaultAuthConfig({
  jwtSecret: process.env.JWT_SECRET!,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET!,
});

// Create utilities
const jwtUtil = new JWTUtil(config);
const cookieUtil = new CookieUtil();

// Use in your API routes
export async function POST(request: NextRequest) {
  const { email, password } = await request.json();

  // Your authentication logic here
  const user = await authenticateUser(email, password);
  const tokens = jwtUtil.generateTokenPair(user);

  const response = NextResponse.json({ success: true });
  cookieUtil.setAuthCookies(response, tokens.accessToken, tokens.refreshToken);

  return response;
}
```

## Quick Start

### 1. Environment Variables

Add these to your `.env.local`:

```env
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
```

### 2. Database Adapter

Create a database adapter that implements the `DatabaseAdapter` interface:

```typescript
// lib/database-adapter.ts
import { DatabaseAdapter, User } from '@abdev/next-auth-custom';

export class MyDatabaseAdapter implements DatabaseAdapter {
  async findUserByEmail(email: string): Promise<User | null> {
    // Implement your database query
    const user = await db.users.findUnique({ where: { email } });
    return user;
  }

  async findUserById(id: string): Promise<User | null> {
    const user = await db.users.findUnique({ where: { id } });
    return user;
  }

  async createUser(
    data: Omit<User, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<User> {
    const user = await db.users.create({
      data: {
        ...data,
        id: generateId(), // Implement your ID generation
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });
    return user;
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    const user = await db.users.update({
      where: { id },
      data: { ...data, updatedAt: new Date() },
    });
    return user;
  }

  async storeRefreshToken(
    userId: string,
    token: string,
    deviceId?: string
  ): Promise<void> {
    await db.refreshTokens.create({
      data: { userId, token, deviceId, createdAt: new Date() },
    });
  }

  async validateRefreshToken(token: string, userId: string): Promise<boolean> {
    const storedToken = await db.refreshTokens.findFirst({
      where: { token, userId, revoked: false },
    });
    return !!storedToken;
  }

  async revokeRefreshToken(token: string, userId: string): Promise<void> {
    await db.refreshTokens.updateMany({
      where: { token, userId },
      data: { revoked: true, revokedAt: new Date() },
    });
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await db.refreshTokens.updateMany({
      where: { userId },
      data: { revoked: true, revokedAt: new Date() },
    });
  }
}
```

### 3. Auth Configuration

```typescript
// lib/auth-config.ts
import { createDefaultAuthConfig } from '@abdev/next-auth-custom';

export const authConfig = createDefaultAuthConfig({
  jwtSecret: process.env.JWT_SECRET!,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET!,
  accessTokenExpiry: 15 * 60, // 15 minutes
  refreshTokenExpiry: 7 * 24 * 60 * 60, // 7 days
  enableTokenRotation: true,
  enableDeviceTracking: false,
});
```

### 4. Auth Service

```typescript
// lib/auth-service.ts
import { createAuthService } from '@abdev/next-auth-custom';
import { authConfig } from './auth-config';
import { MyDatabaseAdapter } from './database-adapter';

const dbAdapter = new MyDatabaseAdapter();
export const authService = createAuthService(authConfig, dbAdapter);
```

### 5. API Routes

```typescript
// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { authService } from '@/lib/auth-service';
import { CookieUtil } from '@abdev/next-auth-custom';

const cookieUtil = new CookieUtil();

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    const result = await authService.login({ email, password });

    if (!result.success) {
      return NextResponse.json({ error: result.error }, { status: 401 });
    }

    const response = NextResponse.json({
      user: result.user,
      success: true,
    });

    // Set HttpOnly cookies
    cookieUtil.setAuthCookies(
      response,
      result.session!.accessToken,
      result.session!.refreshToken
    );

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

```typescript
// app/api/auth/register/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { authService } from '@/lib/auth-service';
import { CookieUtil } from '@abdev/next-auth-custom';

const cookieUtil = new CookieUtil();

export async function POST(request: NextRequest) {
  try {
    const { email, password, name } = await request.json();

    const result = await authService.register({ email, password, name });

    if (!result.success) {
      return NextResponse.json({ error: result.error }, { status: 400 });
    }

    const response = NextResponse.json({
      user: result.user,
      success: true,
    });

    // Set HttpOnly cookies
    cookieUtil.setAuthCookies(
      response,
      result.session!.accessToken,
      result.session!.refreshToken
    );

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

```typescript
// app/api/auth/refresh/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { authService } from '@/lib/auth-service';
import { CookieUtil } from '@abdev/next-auth-custom';

const cookieUtil = new CookieUtil();

export async function POST(request: NextRequest) {
  try {
    const { refreshToken } = cookieUtil.getAuthTokens(request);

    if (!refreshToken) {
      return NextResponse.json({ error: 'No refresh token' }, { status: 401 });
    }

    const result = await authService.refresh(refreshToken);

    if (!result.success) {
      return NextResponse.json({ error: result.error }, { status: 401 });
    }

    const response = NextResponse.json({
      user: result.user,
      success: true,
    });

    // Set new HttpOnly cookies
    cookieUtil.setAuthCookies(
      response,
      result.session!.accessToken,
      result.session!.refreshToken
    );

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

```typescript
// app/api/auth/logout/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { authService } from '@/lib/auth-service';
import { CookieUtil } from '@abdev/next-auth-custom';

const cookieUtil = new CookieUtil();

export async function POST(request: NextRequest) {
  try {
    const { refreshToken } = cookieUtil.getAuthTokens(request);

    if (refreshToken) {
      await authService.logout(refreshToken);
    }

    const response = NextResponse.json({ success: true });

    // Clear cookies
    cookieUtil.clearAuthCookies(response);

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

### 6. Middleware

```typescript
// middleware.ts
import { createAuthMiddleware } from '@abdev/next-auth-custom';
import { authConfig } from './lib/auth-config';
import { MyDatabaseAdapter } from './lib/database-adapter';

const dbAdapter = new MyDatabaseAdapter();

const authMiddleware = createAuthMiddleware({
  config: authConfig,
  dbAdapter,
  middlewareConfig: {
    protectedRoutes: ['/dashboard', '/profile', '/admin'],
    publicRoutes: ['/api/public', '/'],
    authRoutes: ['/api/auth', '/login', '/register'],
    redirectTo: '/login',
  },
});

export default authMiddleware;

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

### 7. Client-side Usage

```typescript
// hooks/useAuth.ts
import { useState, useEffect } from 'react';
import { User } from '@abdev/next-auth-custom';

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch current user on mount
    fetch('/api/auth/me')
      .then((res) => res.json())
      .then((data) => {
        if (data.user) {
          setUser(data.user);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (data.success) {
      setUser(data.user);
      return { success: true };
    } else {
      return { success: false, error: data.error };
    }
  };

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setUser(null);
  };

  return { user, loading, login, logout };
}
```

## API Reference

### Types

#### `User`

```typescript
interface User {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  role?: string;
  createdAt: Date;
  updatedAt: Date;
}
```

#### `AuthConfig`

```typescript
interface AuthConfig {
  jwtSecret: string;
  jwtRefreshSecret: string;
  accessTokenExpiry: number; // in seconds
  refreshTokenExpiry: number; // in seconds
  cookieDomain?: string;
  cookieSecure?: boolean;
  cookieSameSite?: 'strict' | 'lax' | 'none';
  enableTokenRotation?: boolean;
  enableDeviceTracking?: boolean;
}
```

#### `DatabaseAdapter`

```typescript
interface DatabaseAdapter {
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  createUser(data: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User>;
  updateUser(id: string, data: Partial<User>): Promise<User>;
  storeRefreshToken(
    userId: string,
    token: string,
    deviceId?: string
  ): Promise<void>;
  validateRefreshToken(token: string, userId: string): Promise<boolean>;
  revokeRefreshToken(token: string, userId: string): Promise<void>;
  revokeAllUserTokens(userId: string): Promise<void>;
}
```

### Classes

#### `AuthServiceImpl`

Main authentication service class.

```typescript
const authService = new AuthServiceImpl(config, dbAdapter);

// Methods
await authService.register(data: RegisterData): Promise<AuthResponse>
await authService.login(credentials: LoginCredentials): Promise<AuthResponse>
await authService.refresh(refreshToken: string): Promise<AuthResponse>
await authService.logout(refreshToken: string): Promise<AuthResponse>
await authService.validateAccessToken(token: string): Promise<User | null>
await authService.getUserFromToken(token: string): Promise<User | null>
```

#### `JWTUtil`

JWT token utility class.

```typescript
const jwtUtil = new JWTUtil(config);

// Methods
jwtUtil.generateAccessToken(user: User, deviceId?: string): string
jwtUtil.generateRefreshToken(user: User, deviceId?: string): string
jwtUtil.verifyAccessToken(token: string): JWTPayload | null
jwtUtil.verifyRefreshToken(token: string): JWTPayload | null
jwtUtil.generateTokenPair(user: User, deviceId?: string): TokenResponse
jwtUtil.isTokenExpired(token: string, isRefreshToken?: boolean): boolean
jwtUtil.getTokenExpiration(token: string, isRefreshToken?: boolean): number | null
```

#### `CookieUtil`

Cookie management utility class.

```typescript
const cookieUtil = new CookieUtil(options);

// Methods
cookieUtil.setCookie(response: NextResponse, name: string, value: string, options?: CookieOptions): NextResponse
cookieUtil.getCookie(request: NextRequest, name: string): string | undefined
cookieUtil.removeCookie(response: NextResponse, name: string, options?: CookieOptions): NextResponse
cookieUtil.setAuthCookies(response: NextResponse, accessToken: string, refreshToken: string, options?: CookieOptions): NextResponse
cookieUtil.clearAuthCookies(response: NextResponse): NextResponse
cookieUtil.getAuthTokens(request: NextRequest): { accessToken?: string; refreshToken?: string }
```

### Functions

#### `createAuthService(config, dbAdapter)`

Factory function to create an auth service instance.

#### `createDefaultAuthConfig(overrides)`

Helper function to create default auth configuration.

#### `createAuthMiddleware(options)`

Factory function to create Next.js middleware for route protection.

## Security Features

- **HttpOnly Cookies**: Tokens are stored in HttpOnly cookies to prevent XSS attacks
- **Token Rotation**: Optional refresh token rotation for enhanced security
- **Device Tracking**: Optional device-based session management
- **Secure Headers**: Automatic secure cookie settings in production
- **Token Expiration**: Configurable token expiration times
- **Database Validation**: Refresh tokens are validated against database

## Database Schema Examples

### PostgreSQL (with Prisma)

```prisma
model User {
  id        String   @id @default(cuid())
  email     String   @unique
  name      String?
  role      String   @default("user")
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  refreshTokens RefreshToken[]
}

model RefreshToken {
  id        String   @id @default(cuid())
  token     String   @unique
  userId    String
  deviceId  String?
  revoked   Boolean  @default(false)
  revokedAt DateTime?
  createdAt DateTime @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
}
```

### Firestore

```typescript
// Collections structure
users/{userId} = {
  email: string,
  name: string,
  role: string,
  createdAt: timestamp,
  updatedAt: timestamp
}

refreshTokens/{tokenId} = {
  token: string,
  userId: string,
  deviceId: string,
  revoked: boolean,
  revokedAt: timestamp,
  createdAt: timestamp
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you have any questions or need help, please open an issue on GitHub.

# next-auth-custom
