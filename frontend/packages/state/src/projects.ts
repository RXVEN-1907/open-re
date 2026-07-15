import { create } from 'zustand';

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

interface ProjectsState {
  projects: Project[];
  currentProject: Project | null;
  total: number;
  page: number;
  perPage: number;
  isLoading: boolean;
  error: string | null;

  setProjects: (projects: Project[], total: number, page: number, perPage: number) => void;
  setCurrentProject: (project: Project | null) => void;
  addProject: (project: Project) => void;
  updateProject: (id: string, data: Partial<Project>) => void;
  removeProject: (id: string) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
}

export const useProjectsStore = create<ProjectsState>((set) => ({
  projects: [],
  currentProject: null,
  total: 0,
  page: 1,
  perPage: 20,
  isLoading: false,
  error: null,

  setProjects: (projects, total, page, perPage) => {
    set({ projects, total, page, perPage, isLoading: false, error: null });
  },

  setCurrentProject: (project) => {
    set({ currentProject: project });
  },

  addProject: (project) => {
    set((state) => ({
      projects: [project, ...state.projects],
      total: state.total + 1,
    }));
  },

  updateProject: (id, data) => {
    set((state) => ({
      projects: state.projects.map((p) => (p.id === id ? { ...p, ...data } : p)),
      currentProject: state.currentProject?.id === id ? { ...state.currentProject, ...data } : state.currentProject,
    }));
  },

  removeProject: (id) => {
    set((state) => ({
      projects: state.projects.filter((p) => p.id !== id),
      total: state.total - 1,
      currentProject: state.currentProject?.id === id ? null : state.currentProject,
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
}));