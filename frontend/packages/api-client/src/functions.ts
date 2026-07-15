import { ApiClient, PaginatedResponse } from './index';

export interface Function {
  id: string;
  file_id: string;
  name: string;
  address: number;
  size: number;
  is_entry: boolean;
  is_thunk: boolean;
  calling_convention: string | null;
  return_type: string | null;
  parameters: Array<{ name: string; type: string; location: string }>;
  stack_frame_size: number | null;
  cyclomatic_complexity: number | null;
  created_at: string;
  updated_at: string;
}

export interface PseudocodeResponse {
  function_id: string;
  pseudocode: string;
  language: string;
  generated_at: string;
}

export interface CfgResponse {
  function_id: string;
  nodes: Array<{
    id: string;
    address: number;
    instructions: string[];
    is_entry: boolean;
    is_exit: boolean;
  }>;
  edges: Array<{ from: string; to: string; type: string }>;
}

export interface XrefResponse {
  function_id: string;
  xrefs: Array<{
    from_address: number;
    to_address: number;
    type: string;
    from_function: string | null;
    to_function: string | null;
  }>;
}

export interface AnnotationsResponse {
  function_id: string;
  annotations: Array<{
    id: string;
    type: string;
    content: string;
    address: number | null;
    author: string;
    created_at: string;
  }>;
}

export class FunctionsApi {
  constructor(private client: ApiClient) {}

  async list(params?: {
    page?: number;
    per_page?: number;
    project_id?: string;
    file_id?: string;
    name?: string;
    min_address?: number;
    max_address?: number;
  }): Promise<PaginatedResponse<Function>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.project_id) searchParams.append('project_id', params.project_id);
    if (params?.file_id) searchParams.append('file_id', params.file_id);
    if (params?.name) searchParams.append('name', params.name);
    if (params?.min_address) searchParams.append('min_address', params.min_address.toString());
    if (params?.max_address) searchParams.append('max_address', params.max_address.toString());
    
    return this.client.get(`/functions?${searchParams.toString()}`);
  }

  async get(id: string): Promise<Function> {
    return this.client.get(`/functions/${id}`);
  }

  async getPseudocode(id: string): Promise<PseudocodeResponse> {
    return this.client.get(`/functions/${id}/pseudocode`);
  }

  async getCfg(id: string): Promise<CfgResponse> {
    return this.client.get(`/functions/${id}/cfg`);
  }

  async getXrefs(id: string, direction?: 'to' | 'from' | 'both'): Promise<XrefResponse> {
    const searchParams = new URLSearchParams();
    if (direction) searchParams.append('direction', direction);
    return this.client.get(`/functions/${id}/xrefs?${searchParams.toString()}`);
  }

  async getAnnotations(id: string): Promise<AnnotationsResponse> {
    return this.client.get(`/functions/${id}/annotations`);
  }
}