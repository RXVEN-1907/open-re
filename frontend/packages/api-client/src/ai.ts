import { ApiClient } from './index';

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content?: string;
  tool_calls?: Array<{
    id: string;
    name: string;
    arguments: unknown;
  }>;
  tool_call_id?: string;
  name?: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: unknown;
  required: string[];
}

export interface ToolChoice {
  type: 'auto' | 'none' | 'required' | 'specific';
  name?: string;
}

export interface ChatCompletionRequest {
  messages: ChatMessage[];
  tools?: ToolDefinition[];
  tool_choice?: ToolChoice;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  stop?: string[];
  response_format?: 'text' | 'json_object' | { type: 'json_schema'; schema: unknown };
  stream?: boolean;
}

export interface ChatCompletionResponse {
  id: string;
  model: string;
  choices: Array<{
    index: number;
    message: ChatMessage;
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  created: number;
}

export interface StreamChunk {
  type: 'content' | 'tool_call' | 'finish';
  content?: string;
  tool_call?: {
    id: string;
    name: string;
    arguments: unknown;
  };
  finish_reason?: string;
}

export interface AnalyzeFunctionRequest {
  function_id: string;
  project_id: string;
}

export interface AnalyzeFunctionResponse {
  analysis: string;
  model: string;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface TemplateInfo {
  name: string;
  description: string;
  variables: string[];
}

export class AiApi {
  constructor(private client: ApiClient) {}

  async chatCompletion(request: ChatCompletionRequest): Promise<ChatCompletionResponse> {
    return this.client.post('/ai/chat', request);
  }

  async *chatCompletionStream(request: ChatCompletionRequest): AsyncGenerator<StreamChunk> {
    const response = await this.client.client.post('/ai/chat/stream', request, {
      responseType: 'stream',
    });

    for await (const chunk of response.data) {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6);
          if (data === '[DONE]') return;
          
          try {
            const parsed = JSON.parse(data);
            if (parsed.type === 'content') {
              yield { type: 'content', content: parsed.content };
            } else if (parsed.type === 'tool_call') {
              yield { type: 'tool_call', tool_call: parsed.tool_call };
            } else if (parsed.type === 'finish') {
              yield { type: 'finish', finish_reason: parsed.reason };
            }
          } catch {
            // Ignore parse errors
          }
        }
      }
    }
  }

  async analyzeFunction(request: AnalyzeFunctionRequest): Promise<AnalyzeFunctionResponse> {
    return this.client.post('/ai/analyze', request);
  }

  async *analyzeFunctionStream(request: AnalyzeFunctionRequest): AsyncGenerator<StreamChunk> {
    const response = await this.client.client.post('/ai/analyze/stream', request, {
      responseType: 'stream',
    });

    for await (const chunk of response.data) {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6);
          if (data === '[DONE]') return;
          
          try {
            const parsed = JSON.parse(data);
            if (parsed.type === 'content') {
              yield { type: 'content', content: parsed.content };
            } else if (parsed.type === 'tool_call') {
              yield { type: 'tool_call', tool_call: parsed.tool_call };
            } else if (parsed.type === 'finish') {
              yield { type: 'finish', finish_reason: parsed.reason };
            }
          } catch {
            // Ignore parse errors
          }
        }
      }
    }
  }

  async listTemplates(): Promise<TemplateInfo[]> {
    const response = await this.client.get<{ templates: TemplateInfo[] }>('/ai/templates');
    return response.templates;
  }

  async getTemplate(name: string): Promise<TemplateInfo> {
    return this.client.get(`/ai/templates/${name}`);
  }
}