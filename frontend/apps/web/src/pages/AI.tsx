import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { api } from '../lib/api';
import { cn } from '../lib/utils';
import {
  Send,
  Bot,
  Loader2,
  Copy,
  Check,
  FileCode,
  Sparkles,
  X,
} from 'lucide-react';

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

interface ChatResponse {
  id: string;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string | null;
      tool_calls: unknown[] | null;
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  created: number;
}

interface AnalyzeResponse {
  analysis: string;
  model: string;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export default function AI() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: 'system', content: 'You are an expert reverse engineer and malware analyst. Help the user with binary analysis, vulnerability research, and reverse engineering tasks.' },
  ]);
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamingContent, setStreamingContent] = useState('');
  const [selectedModel, setSelectedModel] = useState('default');
  const [temperature, setTemperature] = useState(0.7);
  const [showAnalyzeModal, setShowAnalyzeModal] = useState(false);
  const [analyzeFunctionId, setAnalyzeFunctionId] = useState('');
  const [analyzeProjectId, setAnalyzeProjectId] = useState('');

  const chatMutation = useMutation({
    mutationFn: async (msgs: ChatMessage[]) => {
      const response = await api.post('/api/ai/chat', {
        messages: msgs,
        temperature,
        max_tokens: 4096,
      });
      return response.data as ChatResponse;
    },
    onSuccess: (data) => {
      const assistantMessage = data.choices[0]?.message?.content || '';
      setMessages(prev => [...prev, { role: 'assistant', content: assistantMessage }]);
      setIsStreaming(false);
      setStreamingContent('');
    },
    onError: () => {
      setIsStreaming(false);
      setStreamingContent('');
    },
  });

  const analyzeMutation = useMutation({
    mutationFn: async ({ functionId, projectId }: { functionId: string; projectId: string }) => {
      const response = await api.post('/api/ai/analyze', {
        function_id: functionId,
        project_id: projectId,
      });
      return response.data as AnalyzeResponse;
    },
    onSuccess: (data) => {
      setMessages(prev => [...prev, { role: 'assistant', content: data.analysis }]);
      setShowAnalyzeModal(false);
      setAnalyzeFunctionId('');
      setAnalyzeProjectId('');
    },
  });

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isStreaming) return;

    const userMessage = { role: 'user' as const, content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsStreaming(true);
    setStreamingContent('');

    // For streaming, we'd use the /api/ai/chat/stream endpoint
    // For now, use regular chat
    chatMutation.mutate([...messages, userMessage]);
  };

  const handleAnalyze = (e: React.FormEvent) => {
    e.preventDefault();
    if (!analyzeFunctionId || !analyzeProjectId) return;
    analyzeMutation.mutate({ functionId: analyzeFunctionId, projectId: analyzeProjectId });
  };

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Bot className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">AI Assistant</h1>
            <p className="text-muted-foreground">Powered by local and remote LLMs for reverse engineering</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedModel}
            onChange={(e) => setSelectedModel(e.target.value)}
            className="px-3 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="default">Default (Auto)</option>
            <option value="local">Local Model</option>
            <option value="remote">Remote API</option>
          </select>
          <button
            onClick={() => setShowAnalyzeModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <Sparkles className="h-4 w-4" />
            Analyze Function
          </button>
        </div>
      </div>

      {/* Settings */}
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <label htmlFor="temperature" className="text-sm font-medium">Temperature:</label>
            <input
              id="temperature"
              type="range"
              min="0"
              max="2"
              step="0.1"
              value={temperature}
              onChange={(e) => setTemperature(parseFloat(e.target.value))}
              className="w-32 h-2 bg-muted rounded-lg appearance-none accent-primary"
            />
            <span className="text-sm font-mono text-muted-foreground w-10">{temperature.toFixed(1)}</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span>Model: {selectedModel}</span>
            <span>•</span>
            <span>Max tokens: 4096</span>
          </div>
        </div>
      </div>

      {/* Chat Area */}
      <div className="rounded-lg border border-border bg-card flex-1 min-h-[500px] flex flex-col">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message, index) => (
            <div
              key={index}
              className={cn(
                'flex gap-3 max-w-3xl',
                message.role === 'user' ? 'flex-row-reverse' : 'flex-row'
              )}
            >
              <div
                className={cn(
                  'flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center',
                  message.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted'
                )}
              >
                {message.role === 'user' ? (
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                ) : (
                  <Bot className="h-4 w-4" />
                )}
              </div>
              <div
                className={cn(
                  'flex-1 min-w-0 p-4 rounded-xl',
                  message.role === 'user'
                    ? 'bg-primary text-primary-foreground rounded-tr-none'
                    : 'bg-muted rounded-tl-none'
                )}
              >
                <div className="prose prose-sm max-w-none">
                  {message.content}
                </div>
                {message.role === 'assistant' && (
                  <button
                    onClick={() => copyToClipboard(message.content)}
                    className="mt-2 text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                  >
                    <Copy className="h-3 w-3" />
                    Copy
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Streaming indicator */}
          {isStreaming && (
            <div className="flex gap-3">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-muted flex items-center justify-center">
                <Bot className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0 p-4 rounded-xl bg-muted rounded-tl-none">
                <div className="prose prose-sm max-w-none">
                  {streamingContent}
                  <span className="inline-block w-2 h-4 bg-current animate-pulse ml-1" />
                </div>
              </div>
            </div>
          )}

          {messages.length === 1 && (
            <div className="text-center py-12 text-muted-foreground">
              <Bot className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <h3 className="text-lg font-medium mb-2">Welcome to the AI Assistant</h3>
              <p className="max-w-md mx-auto">
                Ask me anything about reverse engineering, binary analysis, vulnerability research, or malware analysis.
                I can help you understand code, identify vulnerabilities, improve decompilation, and more.
              </p>
              <div className="mt-6 flex flex-wrap justify-center gap-2">
                {[
                  'Explain this function',
                  'Find vulnerabilities',
                  'Improve decompilation',
                  'Recover variable types',
                  'Analyze control flow',
                ].map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() => setInput(suggestion)}
                    className="px-3 py-1.5 rounded-lg border border-border hover:bg-accent text-sm transition-colors"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <div className="border-t border-border p-4">
          <form onSubmit={handleSend} className="flex gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about reverse engineering..."
              rows={1}
              className="flex-1 px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring resize-none min-h-[44px] max-h-32"
              disabled={isStreaming}
            />
            <button
              type="submit"
              disabled={isStreaming || !input.trim()}
              className="flex-shrink-0 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors self-end mb-1"
            >
              {isStreaming ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </button>
          </form>
          <p className="text-xs text-muted-foreground mt-2 text-center">
            Press Enter to send, Shift+Enter for new line
          </p>
        </div>
      </div>

      {/* Analyze Function Modal */}
      {showAnalyzeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md bg-card rounded-lg border border-border p-6 shadow-xl animate-slide-in">
            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Sparkles className="h-5 w-5" />
              Analyze Function with AI
            </h2>
            <form onSubmit={handleAnalyze} className="space-y-4">
              <div>
                <label htmlFor="function_id" className="block text-sm font-medium mb-1">Function ID *</label>
                <input
                  id="function_id"
                  type="text"
                  value={analyzeFunctionId}
                  onChange={(e) => setAnalyzeFunctionId(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="Function UUID"
                  required
                />
              </div>
              <div>
                <label htmlFor="project_id" className="block text-sm font-medium mb-1">Project ID *</label>
                <input
                  id="project_id"
                  type="text"
                  value={analyzeProjectId}
                  onChange={(e) => setAnalyzeProjectId(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="Project UUID"
                  required
                />
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowAnalyzeModal(false)}
                  disabled={analyzeMutation.isPending}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-accent transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={analyzeMutation.isPending || !analyzeFunctionId || !analyzeProjectId}
                  className="px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  {analyzeMutation.isPending ? 'Analyzing...' : 'Analyze'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}