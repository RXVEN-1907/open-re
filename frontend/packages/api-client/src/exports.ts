import { ApiClient, PaginatedResponse } from './index';

export interface Export {
  id: string;
  project_id: string;
  format: string;
  status: string;
  download_url: string | null;
  file_size: number | null;
  created_at: string;
  completed_at: string | null;
}

export interface CreateExportRequest {
  project_id: string;
  format: string;
  include_files?: boolean;
  include_analysis?: boolean;
}

export class ExportsApi {
  constructor(private client: ApiClient) {}

  async list(params?: {
    page?: number;
    per_page?: number;
    project_id?: string;
    status?: string;
  }): Promise<PaginatedResponse<Export>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.project_id) searchParams.append('project_id', params.project_id);
    if (params?.status) searchParams.append('status', params.status);
    
    return this.client.get(`/exports?${searchParams.toString()}`);
  }

  async get(id: string): Promise<Export> {
    return this.client.get(`/exports/${id}`);
  }

  async create(data: CreateExportRequest): Promise<Export> {
    return this.client.post('/exports', data);
  }

  async download(id: string): Promise<Blob> {
    const response = await this.client.client.get(`/exports/${id}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }
}