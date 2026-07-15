import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import { cn, formatRelativeTime } from '../lib/utils';
import {
  Play,
  Search,
  Filter,
  MoreVertical,
  RotateCcw,
  X,
  Loader2,
  CheckCircle,
  AlertCircle,
  Clock,
  BarChart2,
} from 'lucide-react';

interface Analysis {
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

interface AnalysisListResponse {
  analyses: Analysis[];
  total: number;
  page: number;
  per_page: number;
}

const stages = [
  'Identification',
  'Loading',
  'Disassembly',
  'Control Flow',
  'Data Flow',
  'Type Recovery',
  'Decompilation',
  'AI Enrichment',
  'Finalization',
];

export default function Analysis() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedFileId, setSelectedFileId] = useState(searchParams.get('file_id') || '');
  const [showStartModal, setShowStartModal] = useState(false);
  const [newAnalysis, setNewAnalysis] = useState({
    file_id: '',
    stages: [] as string[],
    priority: 'default',
  });

  const { data, isLoading } = useQuery({
    queryKey: ['analyses', page, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '20',
      });
      if (statusFilter) params.append('status', statusFilter);
      const response = await api.get(`/api/analysis?${params}`);
      return response.data as AnalysisListResponse;
    },
  });

  const startMutation = useMutation({
    mutationFn: async (analysis: typeof newAnalysis) => {
      const response = await api.post('/api/analysis', analysis);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analyses'] });
      setShowStartModal(false);
      setNewAnalysis({ file_id: '', stages: [], priority: 'default' });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.post(`/api/analysis/${id}/cancel`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analyses'] });
    },
  });

  const retryMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await api.post(`/api/analysis/${id}/retry`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analyses'] });
    },
  });

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

  const handleStart = (e: React.FormEvent) => {
    e.preventDefault();
    startMutation.mutate(newAnalysis);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Analysis</h1>
          <p className="text-muted-foreground">Manage and monitor binary analysis jobs</p>
        </div>
        <button
          onClick={() => setShowStartModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <Play className="h-4 w-4" />
          Start Analysis
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search analyses..."
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="">All Statuses</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {/* Analyses Table */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto" />
            <p className="mt-4 text-muted-foreground">Loading analyses...</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Job ID</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Type</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Status</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Progress</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Current Stage</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Created</th>
                    <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data?.analyses.map((analysis) => (
                    <tr key={analysis.job_id} className="hover:bg-accent/50 transition-colors">
                      <td className="px-4 py-3 font-mono text-sm">{analysis.job_id.slice(0, 12)}...</td>
                      <td className="px-4 py-3 text-sm">{analysis.job_type}</td>
                      <td className="px-4 py-3">
                        <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs', getStatusBadge(analysis.status))}>
                          {getStatusIcon(analysis.status)}
                          {analysis.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {analysis.progress !== null ? (
                          <div className="flex items-center gap-2 w-48">
                            <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary transition-all"
                                style={{ width: `${analysis.progress * 100}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground w-10 text-right">
                              {Math.round(analysis.progress * 100)}%
                            </span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {analysis.current_stage || (analysis.status === 'running' ? 'Initializing...' : '—')}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">{formatRelativeTime(analysis.created_at)}</td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {analysis.status === 'completed' && (
                            <Link
                              to={`/analysis/${analysis.job_id}`}
                              className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                              title="View Results"
                            >
                              <BarChart2 className="h-4 w-4" />
                            </Link>
                          )}
                          {analysis.status === 'running' && (
                            <button
                              onClick={() => cancelMutation.mutate(analysis.job_id)}
                              disabled={cancelMutation.isPending}
                              className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-destructive transition-colors"
                              title="Cancel"
                            >
                              <X className="h-4 w-4" />
                            </button>
                          )}
                          {(analysis.status === 'failed' || analysis.status === 'cancelled') && (
                            <button
                              onClick={() => retryMutation.mutate(analysis.job_id)}
                              disabled={retryMutation.isPending}
                              className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                              title="Retry"
                            >
                              <RotateCcw className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {!data?.analyses.length && (
                    <tr>
                      <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                        <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p className="text-lg">No analyses found</p>
                        <p className="text-sm">Start your first analysis to see results here</p>
                        <button
                          onClick={() => setShowStartModal(true)}
                          className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                        >
                          <Play className="h-4 w-4" />
                          Start Analysis
                        </button>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {data && data.total > data.per_page && (
              <div className="flex items-center justify-between border-t border-border px-4 py-3">
                <p className="text-sm text-muted-foreground">
                  Showing {(page - 1) * data.per_page + 1} to {Math.min(page * data.per_page, data.total)} of {data.total} analyses
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="p-2 rounded-lg border border-border hover:bg-accent disabled:opacity-50"
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                  </button>
                  <button
                    onClick={() => setPage(p => p + 1)}
                    disabled={page * data.per_page >= data.total}
                    className="p-2 rounded-lg border border-border hover:bg-accent disabled:opacity-50"
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Start Analysis Modal */}
      {showStartModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-2xl bg-card rounded-lg border border-border p-6 shadow-xl animate-slide-in max-h-[80vh] overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Start New Analysis</h2>
            <form onSubmit={handleStart} className="space-y-4">
              <div>
                <label htmlFor="file_id" className="block text-sm font-medium mb-1">File *</label>
                <input
                  id="file_id"
                  type="text"
                  value={newAnalysis.file_id}
                  onChange={(e) => setNewAnalysis(prev => ({ ...prev, file_id: e.target.value }))}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="File UUID"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Stages to run</label>
                <div className="grid grid-cols-2 gap-2">
                  {stages.map((stage) => (
                    <label key={stage} className="flex items-center gap-2 p-2 rounded-lg border border-border hover:bg-accent cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newAnalysis.stages.includes(stage)}
                        onChange={(e) => setNewAnalysis(prev => ({
                          ...prev,
                          stages: e.target.checked
                            ? [...prev.stages, stage]
                            : prev.stages.filter(s => s !== stage)
                        }))}
                        className="h-4 w-4 rounded border-border text-primary focus:ring-primary"
                      />
                      <span className="text-sm">{stage}</span>
                    </label>
                  ))}
                </div>
              </div>
              
              <div>
                <label htmlFor="priority" className="block text-sm font-medium mb-1">Priority</label>
                <select
                  id="priority"
                  value={newAnalysis.priority}
                  onChange={(e) => setNewAnalysis(prev => ({ ...prev, priority: e.target.value }))}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="high">High</option>
                  <option value="default">Default</option>
                  <option value="low">Low</option>
                </select>
              </div>
              
              <div className="flex justify-end gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowStartModal(false)}
                  disabled={startMutation.isPending}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-accent transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={startMutation.isPending || !newAnalysis.file_id.trim()}
                  className="px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  {startMutation.isPending ? 'Starting...' : 'Start Analysis'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}