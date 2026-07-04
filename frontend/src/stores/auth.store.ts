import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

import type { ROLE } from '@lib/constants';

interface AuthState {
  accessToken: string | null;
  user: { id: string; name: string; role: ROLE } | null;
  isHydrated: boolean;
  setTokens: (token: string | null, user: AuthState['user']) => void;
  clearAuth: () => void;
  setHydrated: (v: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      accessToken: null,
      user: null,
      isHydrated: false,
      setTokens: (token, user) => set({ accessToken: token, user }),
      clearAuth: () => set({ accessToken: null, user: null }),
      setHydrated: (v) => set({ isHydrated: v })
    }),
    {
      name: 'auth-storage',
      storage: createJSONStorage(() => localStorage),
      onRehydrateStorage: () => (state) => {
        if (state) {
          state.setHydrated(true);
        }
      },
    }
  )
);
