import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { cn, formatRelativeTime } from '../lib/utils';
import {
  Search,
  Filter,
  FunctionSquare,
  ChevronRight,
} from 'lucide-react';

interface Function {
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

interface FunctionListResponse {
  functions: Function[];
  total: number;
  page: number;
  per_page: number;
}

export default function Functions() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [projectId, setProjectId] = useState('');
  const [fileId, setFileId] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['functions', page, search, projectId, fileId],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '50',
      });
      if (search) params.append('search', search);
      if (projectId) params.append('project_id', projectId);
      if (fileId) params.append('file_id', fileId);
      const response = await api.get(`/api/functions?${params}`);
      return response.data as FunctionListResponse;
    },
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Functions</h1>
          <p className="text-muted-foreground">Browse and analyze functions</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search functions by name..."
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <input
          type="text"
          value={projectId}
          onChange={(e) => setProjectId(e.target.value)}
          placeholder="Project ID (optional)"
          className="px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring w-64"
        />
        <input
          type="text"
          value={fileId}
          onChange={(e) => setFileId(e.target.value)}
          placeholder="File ID (optional)"
          className="px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring w-64"
        />
      </div>

      {/* Functions Table */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto" />
            <p className="mt-4 text-muted-foreground">Loading functions...</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Function</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Address</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Size</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Type</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Complexity</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">File</th>
                    <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data?.functions.map((func) => (
                    <tr key={func.id} className="hover:bg-accent/50 transition-colors">
                      <td className="px-4 py-3">
                        <Link to={`/functions/${func.id}`} className="font-mono font-medium hover:text-primary transition-colors">
                          {func.name}
                        </Link>
                        {func.is_entry && (
                          <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-green-500/10 text-green-700 dark:text-green-400">Entry</span>
                        )}
                        {func.is_thunk && (
                          <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-yellow-500/10 text-yellow-700 dark:text-yellow-400">Thunk</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-sm">0x{func.address.toString(16).toUpperCase()}</td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">{func.size} bytes</td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {func.calling_convention || '—'}
                      </td>
                      <td className="px-4 py-3">
                        {func.cyclomatic_complexity !== null ? (
                          <span className={cn(
                            'px-2 py-0.5 rounded text-xs font-mono',
                            func.cyclomatic_complexity > 20 ? 'bg-red-500/10 text-red-700' :
                            func.cyclomatic_complexity > 10 ? 'bg-yellow-500/10 text-yellow-700' :
                            'bg-green-500/10 text-green-700'
                          )}>
                            {func.cyclomatic_complexity}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground font-mono">
                        {func.file_id.slice(0, 12)}...
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          to={`/functions/${func.id}`}
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors text-sm"
                        >
                          <FunctionSquare className="h-3 w-3" />
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {!data?.functions.length && (
                    <tr>
                      <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                        <FunctionSquare className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p className="text-lg">No functions found</p>
                        <p className="text-sm">Upload and analyze a binary file to discover functions</p>
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
                  Showing {(page - 1) * data.per_page + 1} to {Math.min(page * data.per_page, data.total)} of {data.total} functions
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
    </div>
  );
}