import { ApiClient, PaginatedResponse } from './index';

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

export class UsersApi {
  constructor(private client: ApiClient) {}

  async list(params?: {
    page?: number;
    per_page?: number;
    search?: string;
    is_active?: boolean;
  }): Promise<PaginatedResponse<User>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.search) searchParams.append('search', params.search);
    if (params?.is_active !== undefined) searchParams.append('is_active', params.is_active.toString());
    
    return this.client.get(`/users?${searchParams.toString()}`);
  }

  async get(id: string): Promise<User> {
    return this.client.get(`/users/${id}`);
  }
}