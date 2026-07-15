import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../lib/api';
import { cn, formatRelativeTime } from '../lib/utils';
import {
  ArrowLeft,
  Code,
  GitBranch,
  Search,
  Copy,
  Check,
  AlertCircle,
  FileCode,
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

interface PseudocodeResponse {
  function_id: string;
  pseudocode: string;
  language: string;
  generated_at: string;
}

interface CfgResponse {
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

interface XrefResponse {
  function_id: string;
  xrefs: Array<{
    from_address: number;
    to_address: number;
    type: string;
    from_function: string | null;
    to_function: string | null;
  }>;
}

interface AnnotationsResponse {
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

export default function FunctionDetail() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<'overview' | 'pseudocode' | 'cfg' | 'xrefs' | 'annotations'>('overview');
  const [copied, setCopied] = useState(false);

  const { data: func, isLoading: funcLoading } = useQuery({
    queryKey: ['function', id],
    queryFn: async () => {
      const response = await api.get(`/api/functions/${id}`);
      return response.data as Function;
    },
    enabled: !!id,
  });

  const { data: pseudocode } = useQuery({
    queryKey: ['function-pseudocode', id],
    queryFn: async () => {
      const response = await api.get(`/api/functions/${id}/pseudocode`);
      return response.data as PseudocodeResponse;
    },
    enabled: !!id && activeTab === 'pseudocode',
  });

  const { data: cfg } = useQuery({
    queryKey: ['function-cfg', id],
    queryFn: async () => {
      const response = await api.get(`/api/functions/${id}/cfg`);
      return response.data as CfgResponse;
    },
    enabled: !!id && activeTab === 'cfg',
  });

  const { data: xrefs } = useQuery({
    queryKey: ['function-xrefs', id],
    queryFn: async () => {
      const response = await api.get(`/api/functions/${id}/xrefs`);
      return response.data as XrefResponse;
    },
    enabled: !!id && activeTab === 'xrefs',
  });

  const { data: annotations } = useQuery({
    queryKey: ['function-annotations', id],
    queryFn: async () => {
      const response = await api.get(`/api/functions/${id}/annotations`);
      return response.data as AnnotationsResponse;
    },
    enabled: !!id && activeTab === 'annotations',
  });

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (funcLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    );
  }

  if (!func) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold">Function not found</h2>
        <Link to="/functions" className="text-primary hover:underline mt-2 inline-block">Back to functions</Link>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: FileCode },
    { id: 'pseudocode', label: 'Pseudocode', icon: Code },
    { id: 'cfg', label: 'CFG', icon: GitBranch },
    { id: 'xrefs', label: 'Xrefs', icon: Search },
    { id: 'annotations', label: 'Annotations', icon: AlertCircle },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <Link to="/functions" className="p-2 rounded-lg text-muted-foreground hover:bg-accent transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold font-mono">{func.name}</h1>
            <p className="text-muted-foreground">0x{func.address.toString(16).toUpperCase()} • {func.size} bytes</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {func.is_entry && (
            <span className="px-2 py-0.5 text-xs rounded bg-green-500/10 text-green-700 dark:text-green-400">Entry Point</span>
          )}
          {func.is_thunk && (
            <span className="px-2 py-0.5 text-xs rounded bg-yellow-500/10 text-yellow-700 dark:text-yellow-400">Thunk</span>
          )}
          <button
            onClick={() => copyToClipboard(func.name)}
            className="p-2 rounded-lg text-muted-foreground hover:bg-accent transition-colors"
            title={copied ? 'Copied!' : 'Copy name'}
          >
            {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border">
          <nav className="flex gap-1 px-1" aria-label="Function tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={cn(
                  'flex items-center gap-1 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                )}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-lg border border-border p-4">
                  <p className="text-sm text-muted-foreground">Address</p>
                  <p className="font-mono text-lg font-medium">0x{func.address.toString(16).toUpperCase()}</p>
                </div>
                <div className="rounded-lg border border-border p-4">
                  <p className="text-sm text-muted-foreground">Size</p>
                  <p className="font-mono text-lg font-medium">{func.size} bytes</p>
                </div>
                <div className="rounded-lg border border-border p-4">
                  <p className="text-sm text-muted-foreground">Calling Convention</p>
                  <p className="font-medium">{func.calling_convention || 'Unknown'}</p>
                </div>
                <div className="rounded-lg border border-border p-4">
                  <p className="text-sm text-muted-foreground">Return Type</p>
                  <p className="font-medium font-mono">{func.return_type || 'void'}</p>
                </div>
                <div className="rounded-lg border border-border p-4">
                  <p className="text-sm text-muted-foreground">Stack Frame</p>
                  <p className="font-medium font-mono">{func.stack_frame_size ? `${func.stack_frame_size} bytes` : 'Unknown'}</p>
                </div>
                <div className="rounded-lg border border-border p-4">
                  <p className="text-sm text-muted-foreground">Cyclomatic Complexity</p>
                  <p className={cn(
                    'font-mono text-2xl font-bold',
                    func.cyclomatic_complexity !== null && func.cyclomatic_complexity > 20 ? 'text-red-500' :
                    func.cyclomatic_complexity !== null && func.cyclomatic_complexity > 10 ? 'text-yellow-500' :
                    'text-green-500'
                  )}>
                    {func.cyclomatic_complexity !== null ? func.cyclomatic_complexity : '—'}
                  </p>
                </div>
              </div>

              {func.parameters.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold mb-3">Parameters</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border">
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Name</th>
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Type</th>
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Location</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {func.parameters.map((param, i) => (
                          <tr key={i} className="hover:bg-accent/50">
                            <td className="px-4 py-2 font-mono text-sm">{param.name}</td>
                            <td className="px-4 py-2 font-mono text-sm">{param.type}</td>
                            <td className="px-4 py-2 font-mono text-sm">{param.location}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              <div>
                <h3 className="text-lg font-semibold mb-3">Metadata</h3>
                <dl className="grid gap-4 md:grid-cols-2">
                  <div>
                    <dt className="text-sm text-muted-foreground">Created</dt>
                    <dd className="font-mono text-sm">{formatRelativeTime(func.created_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-muted-foreground">Updated</dt>
                    <dd className="font-mono text-sm">{formatRelativeTime(func.updated_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-muted-foreground">File ID</dt>
                    <dd className="font-mono text-sm">{func.file_id}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-muted-foreground">Function ID</dt>
                    <dd className="font-mono text-sm">{func.id}</dd>
                  </div>
                </dl>
              </div>
            </div>
          )}

          {activeTab === 'pseudocode' && (
            <div>
              {pseudocode ? (
                <div className="rounded-lg border border-border bg-muted p-4 font-mono text-sm overflow-x-auto">
                  <pre className="whitespace-pre-wrap">{pseudocode.pseudocode}</pre>
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <Code className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No pseudocode available</p>
                  <p className="text-sm">Run decompilation analysis to generate pseudocode</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'cfg' && (
            <div>
              {cfg ? (
                <div className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="rounded-lg border border-border p-4">
                      <p className="text-sm text-muted-foreground">Nodes</p>
                      <p className="font-mono text-2xl font-bold">{cfg.nodes.length}</p>
                    </div>
                    <div className="rounded-lg border border-border p-4">
                      <p className="text-sm text-muted-foreground">Edges</p>
                      <p className="font-mono text-2xl font-bold">{cfg.edges.length}</p>
                    </div>
                    <div className="rounded-lg border border-border p-4">
                      <p className="text-sm text-muted-foreground">Entry Nodes</p>
                      <p className="font-mono text-2xl font-bold">
                        {cfg.nodes.filter(n => n.is_entry).length}
                      </p>
                    </div>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border">
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Node</th>
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Address</th>
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Instructions</th>
                          <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Type</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {cfg.nodes.map((node) => (
                          <tr key={node.id} className="hover:bg-accent/50">
                            <td className="px-4 py-2 font-mono text-sm">{node.id}</td>
                            <td className="px-4 py-2 font-mono text-sm">0x{node.address.toString(16).toUpperCase()}</td>
                            <td className="px-4 py-2 font-mono text-sm">{node.instructions.length}</td>
                            <td className="px-4 py-2">
                              <span className={cn(
                                'px-2 py-0.5 rounded text-xs',
                                node.is_entry ? 'bg-green-500/10 text-green-700' :
                                node.is_exit ? 'bg-red-500/10 text-red-700' :
                                'bg-gray-500/10 text-gray-700'
                              )}>
                                {node.is_entry ? 'Entry' : node.is_exit ? 'Exit' : 'Normal'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <GitBranch className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No CFG available</p>
                  <p className="text-sm">Run control flow analysis to generate CFG</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'xrefs' && (
            <div>
              {xrefs ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">From</th>
                        <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">To</th>
                        <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">Type</th>
                        <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">From Function</th>
                        <th className="px-4 py-2 text-left text-sm font-medium text-muted-foreground">To Function</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {xrefs.xrefs.map((xref, i) => (
                        <tr key={i} className="hover:bg-accent/50">
                          <td className="px-4 py-2 font-mono text-sm">0x{xref.from_address.toString(16).toUpperCase()}</td>
                          <td className="px-4 py-2 font-mono text-sm">0x{xref.to_address.toString(16).toUpperCase()}</td>
                          <td className="px-4 py-2">
                            <span className="px-2 py-0.5 rounded text-xs bg-blue-500/10 text-blue-700">{xref.type}</span>
                          </td>
                          <td className="px-4 py-2 font-mono text-sm">{xref.from_function?.slice(0, 12) || '—'}</td>
                          <td className="px-4 py-2 font-mono text-sm">{xref.to_function?.slice(0, 12) || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No cross-references found</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'annotations' && (
            <div>
              {annotations ? (
                annotations.annotations.length > 0 ? (
                  <div className="space-y-4">
                    {annotations.annotations.map((ann) => (
                      <div key={ann.id} className="rounded-lg border border-border p-4">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="px-2 py-0.5 rounded text-xs bg-blue-500/10 text-blue-700">{ann.type}</span>
                              {ann.address && (
                                <span className="font-mono text-sm text-muted-foreground">0x{ann.address.toString(16).toUpperCase()}</span>
                              )}
                            </div>
                            <p className="whitespace-pre-wrap">{ann.content}</p>
                          </div>
                          <div className="text-right text-sm text-muted-foreground">
                            <p>{ann.author}</p>
                            <p>{formatRelativeTime(ann.created_at)}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12 text-muted-foreground">
                    <AlertCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No annotations yet</p>
                    <p className="text-sm">Add comments, labels, or type information</p>
                  </div>
                )
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto" />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}