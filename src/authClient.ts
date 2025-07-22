import { User, Session } from './types';

export interface AuthClientConfig {
  refreshEndpoint: string;
  meEndpoint: string;
  autoRefresh?: boolean;
  refreshThreshold?: number; // seconds before expiry to refresh
}

export interface AuthClientState {
  user: User | null;
  session: Session | null;
  loading: boolean;
  error: string | null;
}

export type AuthClientListener = (state: AuthClientState) => void;

export class AuthClient {
  private config: AuthClientConfig;
  private state: AuthClientState;
  private listeners: AuthClientListener[] = [];
  private refreshTimer: NodeJS.Timeout | null = null;

  constructor(config: AuthClientConfig) {
    this.config = {
      autoRefresh: true,
      refreshThreshold: 60, // 1 minute before expiry
      ...config,
    };

    this.state = {
      user: null,
      session: null,
      loading: true,
      error: null,
    };
  }

  /**
   * Initialize the auth client
   */
  async init(): Promise<void> {
    try {
      await this.getCurrentUser();
    } catch (error) {
      this.setState({
        loading: false,
        error: 'Failed to initialize auth client',
      });
    }
  }

  /**
   * Get current user from server
   */
  async getCurrentUser(): Promise<User | null> {
    try {
      const response = await fetch(this.config.meEndpoint, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = (await response.json()) as any;
        if (data.user) {
          this.setState({
            user: data.user,
            session: data.session || null,
            loading: false,
            error: null,
          });

          // Set up auto refresh if enabled
          if (this.config.autoRefresh && data.session) {
            this.setupAutoRefresh(data.session);
          }

          return data.user;
        }
      }
    } catch (error) {
      console.error('Failed to get current user:', error);
    }

    this.setState({ loading: false, user: null, session: null });
    return null;
  }

  /**
   * Login user
   */
  async login(
    email: string,
    password: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      this.setState({ loading: true, error: null });

      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password }),
      });

      const data = (await response.json()) as any;

      if (data.success && data.user) {
        this.setState({
          user: data.user,
          session: data.session || null,
          loading: false,
          error: null,
        });

        // Set up auto refresh
        if (this.config.autoRefresh && data.session) {
          this.setupAutoRefresh(data.session);
        }

        return { success: true };
      } else {
        this.setState({
          loading: false,
          error: data.error || 'Login failed',
        });
        return { success: false, error: data.error };
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Login failed';
      this.setState({ loading: false, error: errorMessage });
      return { success: false, error: errorMessage };
    }
  }

  /**
   * Register user
   */
  async register(
    email: string,
    password: string,
    name?: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      this.setState({ loading: true, error: null });

      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password, name }),
      });

      const data = (await response.json()) as any;

      if (data.success && data.user) {
        this.setState({
          user: data.user,
          session: data.session || null,
          loading: false,
          error: null,
        });

        // Set up auto refresh
        if (this.config.autoRefresh && data.session) {
          this.setupAutoRefresh(data.session);
        }

        return { success: true };
      } else {
        this.setState({
          loading: false,
          error: data.error || 'Registration failed',
        });
        return { success: false, error: data.error };
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Registration failed';
      this.setState({ loading: false, error: errorMessage });
      return { success: false, error: errorMessage };
    }
  }

  /**
   * Logout user
   */
  async logout(): Promise<void> {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.clearAutoRefresh();
      this.setState({
        user: null,
        session: null,
        loading: false,
        error: null,
      });
    }
  }

  /**
   * Refresh tokens manually
   */
  async refreshTokens(): Promise<{ success: boolean; error?: string }> {
    try {
      const response = await fetch(this.config.refreshEndpoint, {
        method: 'POST',
        credentials: 'include',
      });

      const data = (await response.json()) as any;

      if (data.success && data.session) {
        this.setState({
          session: data.session,
          error: null,
        });

        // Set up auto refresh for new session
        if (this.config.autoRefresh) {
          this.setupAutoRefresh(data.session);
        }

        return { success: true };
      } else {
        return { success: false, error: data.error || 'Token refresh failed' };
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Token refresh failed';
      return { success: false, error: errorMessage };
    }
  }

  /**
   * Set up automatic token refresh
   */
  private setupAutoRefresh(session: Session): void {
    this.clearAutoRefresh();

    if (!this.config.autoRefresh || !session.expiresAt) {
      return;
    }

    const now = Date.now();
    const expiresAt = session.expiresAt * 1000; // Convert to milliseconds
    const refreshThreshold = (this.config.refreshThreshold || 60) * 1000; // Convert to milliseconds

    // Calculate time until refresh
    const timeUntilRefresh = expiresAt - now - refreshThreshold;

    if (timeUntilRefresh > 0) {
      this.refreshTimer = setTimeout(async () => {
        await this.refreshTokens();
      }, timeUntilRefresh);
    } else {
      // Token is already close to expiry, refresh immediately
      this.refreshTokens();
    }
  }

  /**
   * Clear auto refresh timer
   */
  private clearAutoRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  /**
   * Get current state
   */
  getState(): AuthClientState {
    return { ...this.state };
  }

  /**
   * Subscribe to state changes
   */
  subscribe(listener: AuthClientListener): () => void {
    this.listeners.push(listener);

    // Call listener immediately with current state
    listener(this.getState());

    // Return unsubscribe function
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  /**
   * Update state and notify listeners
   */
  private setState(updates: Partial<AuthClientState>): void {
    this.state = { ...this.state, ...updates };
    this.listeners.forEach((listener) => listener(this.getState()));
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return !!this.state.user;
  }

  /**
   * Get current user
   */
  getUser(): User | null {
    return this.state.user;
  }

  /**
   * Get current session
   */
  getSession(): Session | null {
    return this.state.session;
  }

  /**
   * Check if loading
   */
  isLoading(): boolean {
    return this.state.loading;
  }

  /**
   * Get error
   */
  getError(): string | null {
    return this.state.error;
  }
}

/**
 * Create a default auth client instance
 */
export function createAuthClient(
  config?: Partial<AuthClientConfig>
): AuthClient {
  return new AuthClient({
    refreshEndpoint: '/api/auth/refresh',
    meEndpoint: '/api/auth/me',
    autoRefresh: true,
    refreshThreshold: 60,
    ...config,
  });
}
