import { create } from 'zustand';

export interface Analysis {
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

interface AnalysisState {
  analyses: Analysis[];
  currentAnalysis: Analysis | null;
  total: number;
  page: number;
  perPage: number;
  isLoading: boolean;
  error: string | null;
  wsConnected: boolean;

  setAnalyses: (analyses: Analysis[], total: number, page: number, perPage: number) => void;
  setCurrentAnalysis: (analysis: Analysis | null) => void;
  updateAnalysis: (id: string, data: Partial<Analysis>) => void;
  removeAnalysis: (id: string) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
  setWsConnected: (connected: boolean) => void;
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  analyses: [],
  currentAnalysis: null,
  total: 0,
  page: 1,
  perPage: 20,
  isLoading: false,
  error: null,
  wsConnected: false,

  setAnalyses: (analyses, total, page, perPage) => {
    set({ analyses, total, page, perPage, isLoading: false, error: null });
  },

  setCurrentAnalysis: (analysis) => {
    set({ currentAnalysis: analysis });
  },

  updateAnalysis: (id, data) => {
    set((state) => ({
      analyses: state.analyses.map((a) => (a.job_id === id ? { ...a, ...data } : a)),
      currentAnalysis: state.currentAnalysis?.job_id === id ? { ...state.currentAnalysis, ...data } : state.currentAnalysis,
    }));
  },

  removeAnalysis: (id) => {
    set((state) => ({
      analyses: state.analyses.filter((a) => a.job_id !== id),
      total: state.total - 1,
      currentAnalysis: state.currentAnalysis?.job_id === id ? null : state.currentAnalysis,
    }));
  },

  setLoading: (isLoading) => {
    set({ isLoading });
  },

  setError: (error) => {
    set({ error, isLoading: false });
  },

  clearError: () => {
    set({ error: null });
  },

  setWsConnected: (connected) => {
    set({ wsConnected: connected });
  },
}));