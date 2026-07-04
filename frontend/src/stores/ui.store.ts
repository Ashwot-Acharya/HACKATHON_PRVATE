import create from 'zustand';
import { persist } from 'zustand/middleware';

interface UIState {
  sidebarCollapsed: boolean;
  mobileMenuOpen: boolean;
  activeTheme: 'dark' | 'light';
  toggleSidebar: () => void;
  setMobileMenuOpen: (isOpen: boolean) => void;
  setTheme: (t: UIState['activeTheme']) => void;
}

export const useUIStore = create(persist<UIState>((set) => ({
  sidebarCollapsed: false,
  mobileMenuOpen: false,
  activeTheme: 'dark',
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setMobileMenuOpen: (isOpen) => set({ mobileMenuOpen: isOpen }),
  setTheme: (t) => set({ activeTheme: t })
}), { name: 'banksentinel-ui' }));
