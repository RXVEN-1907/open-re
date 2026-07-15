import { ApiClient, PaginatedResponse } from './index';

export interface Plugin {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  plugin_type: string;
  capabilities: string[];
  enabled: boolean;
  config: Record<string, unknown> | null;
  installed_at: string;
  updated_at: string;
}

export interface InstallPluginRequest {
  source: {
    type: 'registry' | 'local' | 'git';
    name?: string;
    path?: string;
    url?: string;
    rev?: string;
  };
  version?: string;
}

export interface ConfigurePluginRequest {
  config: Record<string, unknown>;
}

export class PluginsApi {
  constructor(private client: ApiClient) {}

  async list(params?: {
    page?: number;
    per_page?: number;
    plugin_type?: string;
    enabled?: boolean;
    search?: string;
  }): Promise<PaginatedResponse<Plugin>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.plugin_type) searchParams.append('plugin_type', params.plugin_type);
    if (params?.enabled !== undefined) searchParams.append('enabled', params.enabled.toString());
    if (params?.search) searchParams.append('search', params.search);
    
    return this.client.get(`/plugins?${searchParams.toString()}`);
  }

  async get(id: string): Promise<Plugin> {
    return this.client.get(`/plugins/${id}`);
  }

  async install(request: InstallPluginRequest): Promise<Plugin> {
    return this.client.post('/plugins', request);
  }

  async uninstall(id: string): Promise<void> {
    return this.client.delete(`/plugins/${id}`);
  }

  async enable(id: string): Promise<Plugin> {
    return this.client.post(`/plugins/${id}/enable`);
  }

  async disable(id: string): Promise<Plugin> {
    return this.client.post(`/plugins/${id}/disable`);
  }

  async configure(id: string, config: Record<string, unknown>): Promise<Plugin> {
    return this.client.put(`/plugins/${id}/configure`, { config });
  }
}