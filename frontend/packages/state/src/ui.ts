import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UIState {
  sidebarOpen: boolean;
  theme: 'light' | 'dark' | 'system';
  resolvedTheme: 'light' | 'dark';
  notifications: Array<{
    id: string;
    type: 'info' | 'success' | 'warning' | 'error';
    title: string;
    message: string;
    duration?: number;
  }>;
  modals: Record<string, boolean>;
  drawers: Record<string, boolean>;

  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  setTheme: (theme: 'light' | 'dark' | 'system') => void;
  setResolvedTheme: (theme: 'light' | 'dark') => void;
  addNotification: (notification: Omit<UIState['notifications'][0], 'id'>) => void;
  removeNotification: (id: string) => void;
  openModal: (id: string) => void;
  closeModal: (id: string) => void;
  toggleModal: (id: string) => void;
  openDrawer: (id: string) => void;
  closeDrawer: (id: string) => void;
  toggleDrawer: (id: string) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set, get) => ({
      sidebarOpen: false,
      theme: 'system',
      resolvedTheme: 'light',
      notifications: [],
      modals: {},
      drawers: {},

      toggleSidebar: () => {
        set((state) => ({ sidebarOpen: !state.sidebarOpen }));
      },

      setSidebarOpen: (open) => {
        set({ sidebarOpen: open });
      },

      setTheme: (theme) => {
        set({ theme });
      },

      setResolvedTheme: (resolvedTheme) => {
        set({ resolvedTheme });
      },

      addNotification: (notification) => {
        const id = Math.random().toString(36).substring(2, 15);
        set((state) => ({
          notifications: [...state.notifications, { ...notification, id }],
        }));

        if (notification.duration !== 0) {
          setTimeout(() => {
            get().removeNotification(id);
          }, notification.duration || 5000);
        }
      },

      removeNotification: (id) => {
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        }));
      },

      openModal: (id) => {
        set((state) => ({
          modals: { ...state.modals, [id]: true },
        }));
      },

      closeModal: (id) => {
        set((state) => {
          const { [id]: _, ...rest } = state.modals;
          return { modals: rest };
        });
      },

      toggleModal: (id) => {
        set((state) => ({
          modals: { ...state.modals, [id]: !state.modals[id] },
        }));
      },

      openDrawer: (id) => {
        set((state) => ({
          drawers: { ...state.drawers, [id]: true },
        }));
      },

      closeDrawer: (id) => {
        set((state) => {
          const { [id]: _, ...rest } = state.drawers;
          return { drawers: rest };
        });
      },

      toggleDrawer: (id) => {
        set((state) => ({
          drawers: { ...state.drawers, [id]: !state.drawers[id] },
        }));
      },
    }),
    {
      name: 'ui-storage',
      partialize: (state) => ({
        theme: state.theme,
        sidebarOpen: state.sidebarOpen,
      }),
    }
  )
);