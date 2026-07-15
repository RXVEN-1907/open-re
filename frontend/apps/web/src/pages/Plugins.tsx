import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { cn, formatRelativeTime } from '../lib/utils';
import {
  Plus,
  Search,
  Filter,
  MoreVertical,
  Plug,
  Check,
  X,
  Loader2,
  Settings,
  Trash2,
  ExternalLink,
  Github,
  Package,
} from 'lucide-react';

interface Plugin {
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

interface PluginListResponse {
  plugins: Plugin[];
  total: number;
  page: number;
  per_page: number;
}

interface InstallPluginRequest {
  source: {
    type: 'registry' | 'local' | 'git';
    name?: string;
    path?: string;
    url?: string;
    rev?: string;
  };
  version?: string;
}

export default function Plugins() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [enabledFilter, setEnabledFilter] = useState<'all' | 'enabled' | 'disabled'>('all');
  const [showInstallModal, setShowInstallModal] = useState(false);
  const [installForm, setInstallForm] = useState({
    sourceType: 'registry' as 'registry' | 'local' | 'git',
    sourceValue: '',
    version: '',
  });

  const { data, isLoading } = useQuery({
    queryKey: ['plugins', page, search, typeFilter, enabledFilter],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '20',
      });
      if (search) params.append('search', search);
      if (typeFilter) params.append('plugin_type', typeFilter);
      if (enabledFilter !== 'all') params.append('enabled', enabledFilter === 'enabled' ? 'true' : 'false');
      const response = await api.get(`/api/plugins?${params}`);
      return response.data as PluginListResponse;
    },
  });

  const installMutation = useMutation({
    mutationFn: async (request: InstallPluginRequest) => {
      const response = await api.post('/api/plugins', request);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      setShowInstallModal(false);
      setInstallForm({ sourceType: 'registry', sourceValue: '', version: '' });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enable }: { id: string; enable: boolean }) => {
      const response = await api.post(`/api/plugins/${id}/${enable ? 'enable' : 'disable'}`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });

  const uninstallMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/api/plugins/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });

  const configureMutation = useMutation({
    mutationFn: async ({ id, config }: { id: string; config: Record<string, unknown> }) => {
      const response = await api.put(`/api/plugins/${id}/configure`, { config });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });

  const handleInstall = (e: React.FormEvent) => {
    e.preventDefault();
    const source = installForm.sourceType === 'registry'
      ? { type: 'registry' as const, name: installForm.sourceValue }
      : installForm.sourceType === 'local'
      ? { type: 'local' as const, path: installForm.sourceValue }
      : { type: 'git' as const, url: installForm.sourceValue };
    
    installMutation.mutate({ source, version: installForm.version || undefined });
  };

  const handleToggle = (id: string, enable: boolean) => {
    toggleMutation.mutate({ id, enable });
  };

  const handleUninstall = (id: string) => {
    if (confirm('Are you sure you want to uninstall this plugin?')) {
      uninstallMutation.mutate(id);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'analyzer': return <Search className="h-4 w-4" />;
      case 'loader': return <Package className="h-4 w-4" />;
      case 'exporter': return <ExternalLink className="h-4 w-4" />;
      case 'ui': return <Plug className="h-4 w-4" />;
      default: return <Plug className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Plug className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Plugins</h1>
            <p className="text-muted-foreground">Extend open-re with community plugins</p>
          </div>
        </div>
        <button
          onClick={() => setShowInstallModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Install Plugin
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search plugins..."
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring w-48"
        >
          <option value="">All Types</option>
          <option value="analyzer">Analyzer</option>
          <option value="loader">Loader</option>
          <option value="exporter">Exporter</option>
          <option value="ui">UI Extension</option>
        </select>
        <select
          value={enabledFilter}
          onChange={(e) => setEnabledFilter(e.target.value as 'all' | 'enabled' | 'disabled')}
          className="px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring w-40"
        >
          <option value="all">All</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>

      {/* Plugins Grid */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto" />
            <p className="mt-4 text-muted-foreground">Loading plugins...</p>
          </div>
        ) : (
          <>
            {data?.plugins.length ? (
              <div className="p-4">
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {data.plugins.map((plugin) => (
                    <div key={plugin.id} className="rounded-lg border border-border p-4 hover:bg-accent/50 transition-colors">
                      <div className="flex items-start justify-between gap-4 mb-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                            {getTypeIcon(plugin.plugin_type)}
                          </div>
                          <div>
                            <h3 className="font-semibold">{plugin.name}</h3>
                            <p className="text-sm text-muted-foreground">v{plugin.version} by {plugin.author}</p>
                          </div>
                        </div>
                        <span className={cn(
                          'px-2 py-1 rounded-full text-xs font-medium',
                          plugin.enabled
                            ? 'bg-green-500/10 text-green-700 dark:text-green-400'
                            : 'bg-gray-500/10 text-gray-700 dark:text-gray-400'
                        )}>
                          {plugin.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                      
                      <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{plugin.description}</p>
                      
                      {plugin.capabilities.length > 0 && (
                        <div className="flex flex-wrap gap-1 mb-3">
                          {plugin.capabilities.slice(0, 4).map((cap) => (
                            <span key={cap} className="px-2 py-0.5 rounded text-xs bg-muted text-muted-foreground">
                              {cap}
                            </span>
                          ))}
                          {plugin.capabilities.length > 4 && (
                            <span className="px-2 py-0.5 rounded text-xs bg-muted text-muted-foreground">
                              +{plugin.capabilities.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                      
                      <div className="flex items-center justify-between pt-3 border-t border-border">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleToggle(plugin.id, !plugin.enabled)}
                            disabled={toggleMutation.isPending}
                            className={cn(
                              'inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                              plugin.enabled
                                ? 'bg-green-500/10 text-green-700 hover:bg-green-500/20'
                                : 'bg-primary/10 text-primary hover:bg-primary/20'
                            )}
                          >
                            {plugin.enabled ? <X className="h-3 w-3" /> : <Check className="h-3 w-3" />}
                            {plugin.enabled ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            onClick={() => configureMutation.mutate({ id: plugin.id, config: plugin.config || {} })}
                            disabled={configureMutation.isPending}
                            className="p-2 rounded-lg text-muted-foreground hover:bg-accent transition-colors"
                            title="Configure"
                          >
                            <Settings className="h-4 w-4" />
                          </button>
                        </div>
                        <button
                          onClick={() => handleUninstall(plugin.id)}
                          disabled={uninstallMutation.isPending}
                          className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-destructive transition-colors"
                          title="Uninstall"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Pagination */}
                {data && data.total > data.per_page && (
                  <div className="flex items-center justify-between border-t border-border px-4 py-3">
                    <p className="text-sm text-muted-foreground">
                      Showing {(page - 1) * data.per_page + 1} to {Math.min(page * data.per_page, data.total)} of {data.total} plugins
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
              </div>
            ) : (
              <div className="p-12 text-center">
                <Plug className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium mb-2">No plugins installed</h3>
                <p className="text-muted-foreground mb-6">Install plugins to extend open-re's capabilities</p>
                <button
                  onClick={() => setShowInstallModal(true)}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                >
                  <Plus className="h-4 w-4" />
                  Install Plugin
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {/* Install Modal */}
      {showInstallModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md bg-card rounded-lg border border-border p-6 shadow-xl animate-slide-in">
            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Plus className="h-5 w-5" />
              Install Plugin
            </h2>
            <form onSubmit={handleInstall} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Source Type</label>
                <select
                  value={installForm.sourceType}
                  onChange={(e) => setInstallForm(prev => ({ ...prev, sourceType: e.target.value as 'registry' | 'local' | 'git' }))}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="registry">Registry (by name)</option>
                  <option value="local">Local file/path</option>
                  <option value="git">Git repository</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1">
                  {installForm.sourceType === 'registry' && 'Plugin Name'}
                  {installForm.sourceType === 'local' && 'Local Path'}
                  {installForm.sourceType === 'git' && 'Git URL'}
                </label>
                <input
                  type="text"
                  value={installForm.sourceValue}
                  onChange={(e) => setInstallForm(prev => ({ ...prev, sourceValue: e.target.value }))}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder={
                    installForm.sourceType === 'registry' ? 'plugin-name' :
                    installForm.sourceType === 'local' ? '/path/to/plugin' :
                    'https://github.com/user/plugin.git'
                  }
                  required
                />
              </div>
              
              {installForm.sourceType === 'git' && (
                <div>
                  <label className="block text-sm font-medium mb-1">Revision (optional)</label>
                  <input
                    type="text"
                    value={installForm.version}
                    onChange={(e) => setInstallForm(prev => ({ ...prev, version: e.target.value }))}
                    className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="main, v1.0.0, commit hash..."
                  />
                </div>
              )}
              
              <div className="flex justify-end gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowInstallModal(false)}
                  disabled={installMutation.isPending}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-accent transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={installMutation.isPending || !installForm.sourceValue.trim()}
                  className="px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  {installMutation.isPending ? 'Installing...' : 'Install'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}