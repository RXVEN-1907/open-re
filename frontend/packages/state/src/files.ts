import { create } from 'zustand';

export interface File {
  id: string;
  user_id: string;
  project_id: string | null;
  filename: string;
  content_type: string;
  size: number;
  object_id: string;
  status: string;
  hash: string;
  created_at: string;
  updated_at: string;
}

interface FilesState {
  files: File[];
  currentFile: File | null;
  total: number;
  page: number;
  perPage: number;
  isLoading: boolean;
  error: string | null;
  uploadProgress: Record<string, number>;

  setFiles: (files: File[], total: number, page: number, perPage: number) => void;
  setCurrentFile: (file: File | null) => void;
  addFile: (file: File) => void;
  updateFile: (id: string, data: Partial<File>) => void;
  removeFile: (id: string) => void;
  setUploadProgress: (fileId: string, progress: number) => void;
  clearUploadProgress: (fileId: string) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
}

export const useFilesStore = create<FilesState>((set) => ({
  files: [],
  currentFile: null,
  total: 0,
  page: 1,
  perPage: 20,
  isLoading: false,
  error: null,
  uploadProgress: {},

  setFiles: (files, total, page, perPage) => {
    set({ files, total, page, perPage, isLoading: false, error: null });
  },

  setCurrentFile: (file) => {
    set({ currentFile: file });
  },

  addFile: (file) => {
    set((state) => ({
      files: [file, ...state.files],
      total: state.total + 1,
    }));
  },

  updateFile: (id, data) => {
    set((state) => ({
      files: state.files.map((f) => (f.id === id ? { ...f, ...data } : f)),
      currentFile: state.currentFile?.id === id ? { ...state.currentFile, ...data } : state.currentFile,
    }));
  },

  removeFile: (id) => {
    set((state) => ({
      files: state.files.filter((f) => f.id !== id),
      total: state.total - 1,
      currentFile: state.currentFile?.id === id ? null : state.currentFile,
    }));
  },

  setUploadProgress: (fileId, progress) => {
    set((state) => ({
      uploadProgress: { ...state.uploadProgress, [fileId]: progress },
    }));
  },

  clearUploadProgress: (fileId) => {
    set((state) => {
      const { [fileId]: _, ...rest } = state.uploadProgress;
      return { uploadProgress: rest };
    });
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