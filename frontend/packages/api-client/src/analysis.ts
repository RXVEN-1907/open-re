import { ApiClient, PaginatedResponse } from './index';

export interface Analysis {
  job_id: string;
  job_type: string;
  status: string;
  progress: number | null;
  current_stage: string | null;
  stages_completed: number;
  total_stages: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface AnalysisRequest {
  file_id: string;
  stages?: string[];
  config?: Record<string, unknown>;
  priority?: 'high' | 'default' | 'low';
}

export interface AnalysisStatusResponse {
  job_id: string;
  job_type: string;
  status: string;
  progress: number | null;
  current_stage: string | null;
  stages_completed: number;
  total_stages: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface AnalysisResultsResponse {
  job_id: string;
  result: unknown;
  completed_at: string;
}

export interface CancelResponse {
  job_id: string;
  cancelled: boolean;
}

export class AnalysisApi {
  constructor(private client: ApiClient) {}

  async start(data: AnalysisRequest): Promise<{ job_id: string; status: string }> {
    return this.client.post('/analysis', data);
  }

  async getStatus(id: string): Promise<AnalysisStatusResponse> {
    return this.client.get(`/analysis/${id}`);
  }

  async getResults(id: string): Promise<AnalysisResultsResponse> {
    return this.client.get(`/analysis/${id}/results`);
  }

  async cancel(id: string): Promise<CancelResponse> {
    return this.client.post(`/analysis/${id}/cancel`);
  }

  async retry(id: string): Promise<{ job_id: string; status: string }> {
    return this.client.post(`/analysis/${id}/retry`);
  }

  async list(params?: {
    page?: number;
    per_page?: number;
    status?: string;
  }): Promise<PaginatedResponse<Analysis>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.status) searchParams.append('status', params.status);
    
    return this.client.get(`/analysis?${searchParams.toString()}`);
  }
}