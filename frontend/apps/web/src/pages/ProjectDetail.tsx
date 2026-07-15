import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { cn, formatRelativeTime, formatBytes } from '../lib/utils';
import {
  ArrowLeft,
  FileCode,
  Search,
  Users,
  Link2,
  Download,
  Settings,
  MoreVertical,
  Edit,
  Trash2,
  Globe,
  Lock,
} from 'lucide-react';

interface Project {
  id: string;
  name: string;
  description: string | null;
  owner_id: string;
  is_public: boolean;
  settings: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

interface File {
  id: string;
  filename: string;
  content_type: string;
  size: number;
  status: string;
  hash: string;
  created_at: string;
}

interface Collaborator {
  user_id: string;
  project_id: string;
  role: string;
  added_at: string;
  user: {
    id: string;
    username: string;
    email: string;
    full_name: string | null;
  };
}

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  
  const { data: project, isLoading: projectLoading } = useQuery({
    queryKey: ['project', id],
    queryFn: async () => {
      const response = await api.get(`/api/projects/${id}`);
      return response.data as Project;
    },
    enabled: !!id,
  });

  const { data: files, isLoading: filesLoading } = useQuery({
    queryKey: ['project-files', id],
    queryFn: async () => {
      const response = await api.get(`/api/files?project_id=${id}&per_page=50`);
      return response.data.files as File[];
    },
    enabled: !!id,
  });

  const { data: collaborators } = useQuery({
    queryKey: ['project-collaborators', id],
    queryFn: async () => {
      const response = await api.get(`/api/projects/${id}/collaborators`);
      return response.data as Collaborator[];
    },
    enabled: !!id,
  });

  if (projectLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold">Project not found</h2>
        <Link to="/projects" className="text-primary hover:underline mt-2 inline-block">Back to projects</Link>
      </div>
    );
  }

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      uploaded: 'bg-green-500/10 text-green-700 dark:text-green-400',
      analyzing: 'bg-blue-500/10 text-blue-700 dark:text-blue-400',
      completed: 'bg-green-500/10 text-green-700 dark:text-green-400',
      failed: 'bg-red-500/10 text-red-700 dark:text-red-400',
    };
    return styles[status] || 'bg-gray-500/10 text-gray-700';
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <Link to="/projects" className="p-2 rounded-lg text-muted-foreground hover:bg-accent transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold">{project.name}</h1>
            <p className="text-muted-foreground">{project.description || 'No description'}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={cn(
            'inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm',
            project.is_public
              ? 'bg-green-500/10 text-green-700 dark:text-green-400'
              : 'bg-gray-500/10 text-gray-700 dark:text-gray-400'
          )}>
            {project.is_public ? <Globe className="h-3 w-3" /> : <Lock className="h-3 w-3" />}
            {project.is_public ? 'Public' : 'Private'}
          </span>
          <Link
            to={`/projects/${project.id}/settings`}
            className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            <Settings className="h-5 w-5" />
          </Link>
        </div>
      </div>

      {/* Tabs */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border">
          <nav className="flex gap-4 px-4" aria-label="Project tabs">
            <Link
              to={`/projects/${project.id}`}
              className="border-b-2 border-primary text-primary pb-3 text-sm font-medium"
            >
              Files
            </Link>
            <Link
              to={`/projects/${project.id}/analysis`}
              className="border-b-2 border-transparent text-muted-foreground hover:text-foreground pb-3 text-sm font-medium"
            >
              Analysis
            </Link>
            <Link
              to={`/projects/${project.id}/collaborators`}
              className="border-b-2 border-transparent text-muted-foreground hover:text-foreground pb-3 text-sm font-medium"
            >
              Collaborators ({collaborators?.length || 0})
            </Link>
            <Link
              to={`/projects/${project.id}/exports`}
              className="border-b-2 border-transparent text-muted-foreground hover:text-foreground pb-3 text-sm font-medium"
            >
              Exports
            </Link>
          </nav>
        </div>

        {/* Files Tab Content */}
        <div className="p-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
            <h2 className="text-lg font-semibold">Files ({files?.length || 0})</h2>
            <Link
              to="/files"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              <FileCode className="h-4 w-4" />
              Upload File
            </Link>
          </div>

          {filesLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto" />
            </div>
          ) : (
            <>
              {files && files.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border bg-muted/50">
                        <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">File</th>
                        <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Size</th>
                        <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Status</th>
                        <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Uploaded</th>
                        <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {files.map((file) => (
                        <tr key={file.id} className="hover:bg-accent/50 transition-colors">
                          <td className="px-4 py-3">
                            <Link to={`/files/${file.id}`} className="font-medium hover:text-primary transition-colors">
                              {file.filename}
                            </Link>
                          </td>
                          <td className="px-4 py-3 text-sm text-muted-foreground">{formatBytes(file.size)}</td>
                          <td className="px-4 py-3">
                            <span className={cn('px-2 py-0.5 rounded text-xs', getStatusBadge(file.status))}>
                              {file.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm text-muted-foreground">{formatRelativeTime(file.created_at)}</td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <Link
                                to={`/files/${file.id}`}
                                className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                                title="View"
                              >
                                <FileCode className="h-4 w-4" />
                              </Link>
                              <Link
                                to={`/analysis?file_id=${file.id}`}
                                className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                                title="Analyze"
                              >
                                <Search className="h-4 w-4" />
                              </Link>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-12">
                  <FileCode className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-lg">No files in this project</p>
                  <p className="text-sm text-muted-foreground mb-4">Upload a binary file to start analyzing</p>
                  <Link
                    to="/files"
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                  >
                    <FileCode className="h-4 w-4" />
                    Upload File
                  </Link>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}