import { create } from 'zustand';
import type { Alert } from '@/types/alert.types';

interface AlertStore {
  alerts: Alert[];
  addAlert: (alert: Alert) => void;
  updateAlert: (id: string, updates: Partial<Alert>) => void;
  clearAlerts: () => void;
}

export const useAlertStore = create<AlertStore>((set) => ({
  alerts: [],
  addAlert: (alert) => set((state) => ({
    // Prepend new alerts so they appear at the top
    alerts: [alert, ...state.alerts],
  })),
  updateAlert: (id, updates) => set((state) => ({
    alerts: state.alerts.map((a) => (a.id === id ? { ...a, ...updates } : a)),
  })),
  clearAlerts: () => set({ alerts: [] }),
}));
