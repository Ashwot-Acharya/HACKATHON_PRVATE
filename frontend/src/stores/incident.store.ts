import create from 'zustand';

interface IncidentState {
  activeIncidentId: string | null;
  selectedAlertIds: string[];
  setActiveIncident: (id: string | null) => void;
  toggleAlertSelection: (id: string) => void;
  clearSelection: () => void;
}

export const useIncidentStore = create<IncidentState>((set, get) => ({
  activeIncidentId: null,
  selectedAlertIds: [],
  setActiveIncident: (id) => set({ activeIncidentId: id }),
  toggleAlertSelection: (id) => {
    const selected = new Set(get().selectedAlertIds);
    if (selected.has(id)) selected.delete(id);
    else selected.add(id);
    set({ selectedAlertIds: Array.from(selected) });
  },
  clearSelection: () => set({ selectedAlertIds: [] })
}));
