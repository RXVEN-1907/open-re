import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { cn, formatRelativeTime, formatBytes } from '../lib/utils';
import {
  FolderGit2,
  FileCode,
  Search,
  FunctionSquare,
  Bot,
  TrendingUp,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
} from 'lucide-react';

interface Project {
  id: string;
  name: string;
  description: string | null;
  is_public: boolean;
  created_at: string;
  updated_at: string;
  file_count: number;
}

interface File {
  id: string;
  filename: string;
  size: number;
  status: string;
  created_at: string;
}

interface Analysis {
  job_id: string;
  job_type: string;
  status: string;
  progress: number | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

interface Stats {
  projects: number;
  files: number;
  analyses: number;
  functions: number;
}

export default function Dashboard() {
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const response = await api.get('/api/stats');
      return response.data as Stats;
    },
  });

  const { data: recentProjects } = useQuery({
    queryKey: ['projects', 'recent'],
    queryFn: async () => {
      const response = await api.get('/api/projects?per_page=5');
      return response.data.projects as Project[];
    },
  });

  const { data: recentFiles } = useQuery({
    queryKey: ['files', 'recent'],
    queryFn: async () => {
      const response = await api.get('/api/files?per_page=5');
      return response.data.files as File[];
    },
  });

  const { data: recentAnalyses } = useQuery({
    queryKey: ['analyses', 'recent'],
    queryFn: async () => {
      const response = await api.get('/api/analysis?per_page=5');
      return response.data.analyses as Analysis[];
    },
  });

  const statCards = [
    { name: 'Projects', value: stats?.projects || 0, icon: FolderGit2, color: 'text-blue-500', bg: 'bg-blue-500/10' },
    { name: 'Files', value: stats?.files || 0, icon: FileCode, color: 'text-green-500', bg: 'bg-green-500/10' },
    { name: 'Analyses', value: stats?.analyses || 0, icon: Search, color: 'text-purple-500', bg: 'bg-purple-500/10' },
    { name: 'Functions', value: stats?.functions || 0, icon: FunctionSquare, color: 'text-orange-500', bg: 'bg-orange-500/10' },
  ];

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      queued: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400',
      running: 'bg-blue-500/10 text-blue-700 dark:text-blue-400',
      completed: 'bg-green-500/10 text-green-700 dark:text-green-400',
      failed: 'bg-red-500/10 text-red-700 dark:text-red-400',
      cancelled: 'bg-gray-500/10 text-gray-700 dark:text-gray-400',
    };
    return styles[status] || 'bg-gray-500/10 text-gray-700';
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-3 w-3" />;
      case 'failed': return <AlertCircle className="h-3 w-3" />;
      case 'running': return <Loader2 className="h-3 w-3 animate-spin" />;
      default: return <Clock className="h-3 w-3" />;
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">Overview of your reverse engineering projects</p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <div key={stat.name} className="rounded-lg border border-border bg-card p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">{stat.name}</p>
                <p className="text-3xl font-bold mt-1">{stat.value.toLocaleString()}</p>
              </div>
              <div className={cn('rounded-lg p-3', stat.bg)}>
                <stat.icon className={cn('h-6 w-6', stat.color)} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Activity */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Recent Projects */}
        <div className="rounded-lg border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-lg font-semibold">Recent Projects</h2>
            <a href="/projects" className="text-sm text-primary hover:underline">View all</a>
          </div>
          <div className="divide-y divide-border">
            {recentProjects?.slice(0, 5).map((project) => (
              <div key={project.id} className="px-4 py-3 hover:bg-accent/50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="min-w-0 flex-1">
                    <p className="font-medium truncate">{project.name}</p>
                    <p className="text-sm text-muted-foreground truncate">
                      {project.file_count} files • {formatRelativeTime(project.updated_at)}
                    </p>
                  </div>
                  <span className={cn('px-2 py-0.5 rounded text-xs', project.is_public ? 'bg-green-500/10 text-green-700' : 'bg-gray-500/10 text-gray-700')}>
                    {project.is_public ? 'Public' : 'Private'}
                  </span>
                </div>
              </div>
            ))}
            {!recentProjects?.length && (
              <div className="px-4 py-8 text-center text-muted-foreground">
                <FolderGit2 className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No projects yet</p>
                <a href="/projects" className="text-primary hover:underline mt-2 inline-block">Create one</a>
              </div>
            )}
          </div>
        </div>

        {/* Recent Files */}
        <div className="rounded-lg border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-lg font-semibold">Recent Files</h2>
            <a href="/files" className="text-sm text-primary hover:underline">View all</a>
          </div>
          <div className="divide-y divide-border">
            {recentFiles?.slice(0, 5).map((file) => (
              <div key={file.id} className="px-4 py-3 hover:bg-accent/50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="min-w-0 flex-1">
                    <p className="font-medium truncate">{file.filename}</p>
                    <p className="text-sm text-muted-foreground">
                      {formatBytes(file.size)} • {formatRelativeTime(file.created_at)}
                    </p>
                  </div>
                  <span className={cn('px-2 py-0.5 rounded text-xs', getStatusBadge(file.status))}>
                    {file.status}
                  </span>
                </div>
              </div>
            ))}
            {!recentFiles?.length && (
              <div className="px-4 py-8 text-center text-muted-foreground">
                <FileCode className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No files uploaded</p>
                <a href="/files" className="text-primary hover:underline mt-2 inline-block">Upload one</a>
              </div>
            )}
          </div>
        </div>

        {/* Recent Analyses */}
        <div className="rounded-lg border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-lg font-semibold">Recent Analyses</h2>
            <a href="/analysis" className="text-sm text-primary hover:underline">View all</a>
          </div>
          <div className="divide-y divide-border">
            {recentAnalyses?.slice(0, 5).map((analysis) => (
              <div key={analysis.job_id} className="px-4 py-3 hover:bg-accent/50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={cn('px-2 py-0.5 rounded text-xs', getStatusBadge(analysis.status))}>
                        {getStatusIcon(analysis.status)}
                        {analysis.status}
                      </span>
                      <span className="text-sm text-muted-foreground">{analysis.job_type}</span>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {analysis.progress !== null ? `${Math.round(analysis.progress * 100)}% complete` : 'Queued'}
                      {' • '}
                      {formatRelativeTime(analysis.created_at)}
                    </p>
                  </div>
                  {analysis.progress !== null && analysis.progress < 1 && (
                    <div className="w-24 h-1.5 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary transition-all"
                        style={{ width: `${analysis.progress * 100}%` }}
                      />
                    </div>
                  )}
                </div>
              </div>
            ))}
            {!recentAnalyses?.length && (
              <div className="px-4 py-8 text-center text-muted-foreground">
                <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No analyses run yet</p>
                <a href="/analysis" className="text-primary hover:underline mt-2 inline-block">Start one</a>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="rounded-lg border border-border bg-card p-6">
        <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
        <div className="flex flex-wrap gap-4">
          <a href="/projects" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors">
            <FolderGit2 className="h-4 w-4" />
            New Project
          </a>
          <a href="/files" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-background hover:bg-accent transition-colors">
            <FileCode className="h-4 w-4" />
            Upload File
          </a>
          <a href="/analysis" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-background hover:bg-accent transition-colors">
            <Search className="h-4 w-4" />
            Start Analysis
          </a>
          <a href="/ai" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-background hover:bg-accent transition-colors">
            <Bot className="h-4 w-4" />
            AI Assistant
          </a>
        </div>
      </div>
    </div>
  );
}