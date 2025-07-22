export interface User {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  role?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Session {
  user: User;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  deviceId?: string;
}

export interface JWTPayload {
  userId: string;
  email: string;
  role?: string;
  deviceId?: string;
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
}

export interface AuthConfig {
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

export interface LoginCredentials {
  email: string;
  password: string;
  deviceId?: string;
}

export interface RegisterData {
  email: string;
  password: string;
  name?: string;
  role?: string;
}

export interface AuthResponse {
  success: boolean;
  user?: User;
  session?: Session;
  error?: string;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  maxAge: number;
  domain?: string;
  path: string;
}

export interface MiddlewareConfig {
  protectedRoutes?: string[];
  publicRoutes?: string[];
  authRoutes?: string[];
  redirectTo?: string;
}

export interface DatabaseAdapter {
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

export interface AuthService {
  login(credentials: LoginCredentials): Promise<AuthResponse>;
  register(data: RegisterData): Promise<AuthResponse>;
  refresh(refreshToken: string): Promise<AuthResponse>;
  logout(refreshToken: string): Promise<AuthResponse>;
  validateAccessToken(token: string): Promise<User | null>;
  getUserFromToken(token: string): Promise<User | null>;
}
