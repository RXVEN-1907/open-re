import { ApiClient } from './index';

export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface LoginRequest {
  email: string;
  password: string;
  remember_me?: boolean;
}

export interface RegisterRequest {
  email: string;
  username: string;
  password: string;
  full_name?: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  expires_at: string | null;
  last_used: string | null;
  created_at: string;
}

export interface CreateApiKeyRequest {
  name: string;
  scopes: string[];
  expires_at?: string;
}

export interface CreateApiKeyResponse {
  api_key: string;
  key: ApiKey;
}

export class AuthApi {
  constructor(private client: ApiClient) {}

  async login(data: LoginRequest): Promise<LoginResponse> {
    return this.client.post('/auth/login', data);
  }

  async register(data: RegisterRequest): Promise<LoginResponse> {
    return this.client.post('/auth/register', data);
  }

  async refreshToken(data: RefreshTokenRequest): Promise<LoginResponse> {
    return this.client.post('/auth/refresh', data);
  }

  async logout(): Promise<void> {
    return this.client.post('/auth/logout');
  }

  async getCurrentUser(): Promise<User> {
    return this.client.get('/auth/me');
  }

  async changePassword(data: ChangePasswordRequest): Promise<void> {
    return this.client.put('/auth/password', data);
  }

  async listApiKeys(): Promise<ApiKey[]> {
    return this.client.get('/auth/api-keys');
  }

  async createApiKey(data: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return this.client.post('/auth/api-keys', data);
  }

  async revokeApiKey(id: string): Promise<void> {
    return this.client.delete(`/auth/api-keys/${id}`);
  }
}