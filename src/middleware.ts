import { NextRequest, NextResponse } from 'next/server';
import { AuthConfig, MiddlewareConfig, DatabaseAdapter } from './types';
import { JWTUtil } from './jwt.util';
import { CookieUtil } from './cookie.util';

export interface AuthMiddlewareOptions {
  config: AuthConfig;
  dbAdapter: DatabaseAdapter;
  middlewareConfig?: MiddlewareConfig;
}

export function createAuthMiddleware(options: AuthMiddlewareOptions) {
  const { config, dbAdapter, middlewareConfig = {} } = options;
  const jwtUtil = new JWTUtil(config);
  const cookieUtil = new CookieUtil({
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite,
    domain: config.cookieDomain,
  });

  return async function authMiddleware(
    request: NextRequest
  ): Promise<NextResponse | undefined> {
    const { pathname } = request.nextUrl;

    // Check if route is public
    if (isPublicRoute(pathname, middlewareConfig)) {
      return NextResponse.next();
    }

    // Check if route is auth route (login, register, etc.)
    if (isAuthRoute(pathname, middlewareConfig)) {
      return NextResponse.next();
    }

    // Get tokens from cookies
    const { accessToken, refreshToken } = cookieUtil.getAuthTokens(request);

    // If no access token, redirect to login
    if (!accessToken) {
      return redirectToLogin(request, middlewareConfig);
    }

    // Validate access token
    const user = await jwtUtil.verifyAccessToken(accessToken);
    if (!user) {
      // Access token is invalid, try to refresh
      if (refreshToken) {
        const refreshResult = await attemptTokenRefresh(
          refreshToken,
          dbAdapter,
          jwtUtil
        );
        if (refreshResult.success && refreshResult.session) {
          // Create new response with updated cookies
          const response = NextResponse.next();
          cookieUtil.setAuthCookies(
            response,
            refreshResult.session.accessToken,
            refreshResult.session.refreshToken
          );
          return response;
        }
      }

      // Both tokens are invalid, redirect to login
      return redirectToLogin(request, middlewareConfig);
    }

    // Check if access token is expired
    if (jwtUtil.isTokenExpired(accessToken)) {
      // Try to refresh token
      if (refreshToken) {
        const refreshResult = await attemptTokenRefresh(
          refreshToken,
          dbAdapter,
          jwtUtil
        );
        if (refreshResult.success && refreshResult.session) {
          // Create new response with updated cookies
          const response = NextResponse.next();
          cookieUtil.setAuthCookies(
            response,
            refreshResult.session.accessToken,
            refreshResult.session.refreshToken
          );
          return response;
        }
      }

      // Cannot refresh, redirect to login
      return redirectToLogin(request, middlewareConfig);
    }

    // Token is valid, proceed
    return NextResponse.next();
  };
}

/**
 * Check if the current route is public
 */
function isPublicRoute(pathname: string, config: MiddlewareConfig): boolean {
  if (config.publicRoutes) {
    return config.publicRoutes.some(
      (route) => pathname.startsWith(route) || pathname === route
    );
  }

  // Default public routes
  const defaultPublicRoutes = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/refresh',
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
  ];

  return defaultPublicRoutes.some(
    (route) => pathname.startsWith(route) || pathname === route
  );
}

/**
 * Check if the current route is an auth route
 */
function isAuthRoute(pathname: string, config: MiddlewareConfig): boolean {
  if (config.authRoutes) {
    return config.authRoutes.some(
      (route) => pathname.startsWith(route) || pathname === route
    );
  }

  // Default auth routes
  const defaultAuthRoutes = [
    '/api/auth',
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
  ];

  return defaultAuthRoutes.some(
    (route) => pathname.startsWith(route) || pathname === route
  );
}

/**
 * Check if the current route is protected
 */
function isProtectedRoute(pathname: string, config: MiddlewareConfig): boolean {
  if (config.protectedRoutes) {
    return config.protectedRoutes.some(
      (route) => pathname.startsWith(route) || pathname === route
    );
  }

  // Default protected routes
  const defaultProtectedRoutes = [
    '/dashboard',
    '/profile',
    '/admin',
    '/api/protected',
  ];

  return defaultProtectedRoutes.some(
    (route) => pathname.startsWith(route) || pathname === route
  );
}

/**
 * Redirect to login page
 */
function redirectToLogin(
  request: NextRequest,
  config: MiddlewareConfig
): NextResponse {
  const loginUrl = config.redirectTo || '/login';
  const url = request.nextUrl.clone();
  url.pathname = loginUrl;
  url.searchParams.set('redirect', request.nextUrl.pathname);

  return NextResponse.redirect(url);
}

/**
 * Attempt to refresh the access token using refresh token
 */
async function attemptTokenRefresh(
  refreshToken: string,
  dbAdapter: DatabaseAdapter,
  jwtUtil: JWTUtil
): Promise<{ success: boolean; session?: any }> {
  try {
    const payload = jwtUtil.verifyRefreshToken(refreshToken);
    if (!payload) {
      return { success: false };
    }

    // Check if token is expired
    if (jwtUtil.isTokenExpired(refreshToken, true)) {
      return { success: false };
    }

    // Validate refresh token in database
    const isValid = await dbAdapter.validateRefreshToken(
      refreshToken,
      payload.userId
    );
    if (!isValid) {
      return { success: false };
    }

    // Get user
    const user = await dbAdapter.findUserById(payload.userId);
    if (!user) {
      return { success: false };
    }

    // Generate new access token
    const {
      accessToken,
      refreshToken: newRefreshToken,
      expiresAt,
    } = jwtUtil.generateTokenPair(user, payload.deviceId);

    return {
      success: true,
      session: {
        user,
        accessToken,
        refreshToken: newRefreshToken,
        expiresAt,
        deviceId: payload.deviceId,
      },
    };
  } catch {
    return { success: false };
  }
}

/**
 * Helper function to get user from request
 */
export async function getUserFromRequest(
  request: NextRequest,
  config: AuthConfig,
  dbAdapter: DatabaseAdapter
): Promise<any | null> {
  const jwtUtil = new JWTUtil(config);
  const cookieUtil = new CookieUtil();

  const { accessToken } = cookieUtil.getAuthTokens(request);
  if (!accessToken) return null;

  return jwtUtil.verifyAccessToken(accessToken);
}
