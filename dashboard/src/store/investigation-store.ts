import { create } from "zustand";

type InvestigationState = {
  ip: string | null;
  open: boolean;
  openIp: (ip: string) => void;
  close: () => void;
};

export const useInvestigationStore = create<InvestigationState>((set) => ({
  ip: null,
  open: false,
  openIp: (ip) => set({ ip: ip.trim(), open: true }),
  close: () => set({ open: false, ip: null }),
}));
