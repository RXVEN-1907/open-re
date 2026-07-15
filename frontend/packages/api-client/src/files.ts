import { ApiClient, PaginatedResponse } from './index';

export interface File {
  id: string;
  user_id: string;
  project_id: string | null;
  filename: string;
  content_type: string;
  size: number;
  object_id: string;
  status: string;
  hash: string;
  created_at: string;
  updated_at: string;
}

export interface UploadFileRequest {
  project_id?: string;
}

export interface StartAnalysisRequest {
  stages?: string[];
  config?: Record<string, unknown>;
  priority?: 'high' | 'default' | 'low';
}

export interface AnalysisResponse {
  job_id: string;
  status: string;
}

export class FilesApi {
  constructor(private client: ApiClient) {}

  async list(params?: {
    page?: number;
    per_page?: number;
    project_id?: string;
    status?: string;
  }): Promise<PaginatedResponse<File>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.project_id) searchParams.append('project_id', params.project_id);
    if (params?.status) searchParams.append('status', params.status);
    
    return this.client.get(`/files?${searchParams.toString()}`);
  }

  async get(id: string): Promise<File> {
    return this.client.get(`/files/${id}`);
  }

  async upload(file: File, projectId?: string, onProgress?: (progress: number) => void): Promise<File> {
    const formData = new FormData();
    formData.append('file', file);
    if (projectId) {
      formData.append('project_id', projectId);
    }
    
    return this.client.upload('/files', formData, onProgress);
  }

  async delete(id: string): Promise<void> {
    return this.client.delete(`/files/${id}`);
  }

  async download(id: string): Promise<Blob> {
    const response = await this.client.client.get(`/files/${id}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  async startAnalysis(id: string, data: StartAnalysisRequest): Promise<AnalysisResponse> {
    return this.client.post(`/files/${id}/analysis`, data);
  }
}