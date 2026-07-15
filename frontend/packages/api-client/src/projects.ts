import { ApiClient, PaginatedResponse } from './index';

export interface Project {
  id: string;
  name: string;
  description: string | null;
  owner_id: string;
  is_public: boolean;
  settings: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface CreateProjectRequest {
  name: string;
  description?: string;
  is_public?: boolean;
  settings?: Record<string, unknown>;
}

export interface UpdateProjectRequest {
  name?: string;
  description?: string;
  is_public?: boolean;
  settings?: Record<string, unknown>;
}

export interface Collaborator {
  user_id: string;
  project_id: string;
  role: string;
  added_at: string;
  user?: {
    id: string;
    username: string;
    email: string;
    full_name: string | null;
  };
}

export interface Invite {
  id: string;
  project_id: string;
  email: string;
  role: string;
  token: string;
  expires_at: string;
  created_at: string;
  accepted_at: string | null;
}

export interface ShareLink {
  id: string;
  project_id: string;
  token: string;
  permission: string;
  expires_at: string | null;
  max_uses: number | null;
  uses: number;
  created_at: string;
}

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

export class ProjectsApi {
  constructor(private client: ApiClient) {}

  async list(params?: {
    page?: number;
    per_page?: number;
    search?: string;
    project_id?: string;
  }): Promise<PaginatedResponse<Project>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    if (params?.search) searchParams.append('search', params.search);
    if (params?.project_id) searchParams.append('project_id', params.project_id);
    
    return this.client.get(`/projects?${searchParams.toString()}`);
  }

  async get(id: string): Promise<Project> {
    return this.client.get(`/projects/${id}`);
  }

  async create(data: CreateProjectRequest): Promise<Project> {
    return this.client.post('/projects', data);
  }

  async update(id: string, data: UpdateProjectRequest): Promise<Project> {
    return this.client.put(`/projects/${id}`, data);
  }

  async delete(id: string): Promise<void> {
    return this.client.delete(`/projects/${id}`);
  }

  // Collaborators
  async listCollaborators(projectId: string): Promise<Collaborator[]> {
    return this.client.get(`/projects/${projectId}/collaborators`);
  }

  async addCollaborator(projectId: string, userId: string, role: string): Promise<Collaborator> {
    return this.client.post(`/projects/${projectId}/collaborators`, { user_id: userId, role });
  }

  async removeCollaborator(projectId: string, userId: string): Promise<void> {
    return this.client.delete(`/projects/${projectId}/collaborators/${userId}`);
  }

  // Invites
  async listInvites(projectId: string): Promise<Invite[]> {
    return this.client.get(`/projects/${projectId}/invites`);
  }

  async createInvite(projectId: string, data: { email: string; role: string; expires_at?: string }): Promise<Invite> {
    return this.client.post(`/projects/${projectId}/invites`, data);
  }

  async revokeInvite(projectId: string, inviteId: string): Promise<void> {
    return this.client.delete(`/projects/${projectId}/invites/${inviteId}`);
  }

  // Share links
  async createShareLink(projectId: string, data: { permission: string; expires_at?: string; max_uses?: number }): Promise<ShareLink> {
    return this.client.post(`/projects/${projectId}/share`, data);
  }

  // Exports
  async createExport(projectId: string, data: { format: string; include_files?: boolean; include_analysis?: boolean }): Promise<Export> {
    return this.client.post(`/projects/${projectId}/export`, data);
  }

  async listExports(projectId: string, params?: { page?: number; per_page?: number }): Promise<PaginatedResponse<Export>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());
    
    return this.client.get(`/projects/${projectId}/exports?${searchParams.toString()}`);
  }
}