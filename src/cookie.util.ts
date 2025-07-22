import { serialize, parse } from 'cookie';
import { NextRequest, NextResponse } from 'next/server';
import { CookieOptions } from './types';

export class CookieUtil {
  private defaultOptions: CookieOptions;

  constructor(defaultOptions: Partial<CookieOptions> = {}) {
    this.defaultOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
      ...defaultOptions,
    };
  }

  /**
   * Set an HttpOnly cookie in the response
   */
  setCookie(
    response: NextResponse,
    name: string,
    value: string,
    options: Partial<CookieOptions> = {}
  ): NextResponse {
    const cookieOptions = { ...this.defaultOptions, ...options };

    const cookieString = serialize(name, value, cookieOptions);
    response.headers.append('Set-Cookie', cookieString);

    return response;
  }

  /**
   * Get a cookie value from the request
   */
  getCookie(request: NextRequest, name: string): string | undefined {
    const cookieHeader = request.headers.get('cookie');
    if (!cookieHeader) return undefined;

    const cookies = parse(cookieHeader);
    return cookies[name];
  }

  /**
   * Remove a cookie by setting it to expire in the past
   */
  removeCookie(
    response: NextResponse,
    name: string,
    options: Partial<CookieOptions> = {}
  ): NextResponse {
    const cookieOptions = {
      ...this.defaultOptions,
      ...options,
      maxAge: -1,
      expires: new Date(0),
    };

    const cookieString = serialize(name, '', cookieOptions);
    response.headers.append('Set-Cookie', cookieString);

    return response;
  }

  /**
   * Set authentication cookies (access and refresh tokens)
   */
  setAuthCookies(
    response: NextResponse,
    accessToken: string,
    refreshToken: string,
    options: Partial<CookieOptions> = {}
  ): NextResponse {
    const accessTokenOptions = {
      ...options,
      maxAge: 15 * 60, // 15 minutes
    };

    const refreshTokenOptions = {
      ...options,
      maxAge: 7 * 24 * 60 * 60, // 7 days
    };

    this.setCookie(response, 'access_token', accessToken, accessTokenOptions);
    this.setCookie(
      response,
      'refresh_token',
      refreshToken,
      refreshTokenOptions
    );

    return response;
  }

  /**
   * Clear authentication cookies
   */
  clearAuthCookies(response: NextResponse): NextResponse {
    this.removeCookie(response, 'access_token');
    this.removeCookie(response, 'refresh_token');

    return response;
  }

  /**
   * Get authentication tokens from cookies
   */
  getAuthTokens(request: NextRequest): {
    accessToken?: string;
    refreshToken?: string;
  } {
    return {
      accessToken: this.getCookie(request, 'access_token'),
      refreshToken: this.getCookie(request, 'refresh_token'),
    };
  }

  /**
   * Parse cookies from a cookie header string
   */
  parseCookies(cookieHeader: string): Record<string, string> {
    return parse(cookieHeader);
  }

  /**
   * Serialize a cookie value
   */
  serializeCookie(
    name: string,
    value: string,
    options: Partial<CookieOptions> = {}
  ): string {
    const cookieOptions = { ...this.defaultOptions, ...options };
    return serialize(name, value, cookieOptions);
  }
}
