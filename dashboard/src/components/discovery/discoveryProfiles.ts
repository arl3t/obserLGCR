import type { ScanProfile } from "@/api/discovery";

export interface ProfileMeta {
  id: ScanProfile;
  label: string;
  short: string;
  args: string;
  duration: "rápido" | "medio" | "lento" | "muy lento";
  icon: string;
  useCase: string;
}

export const NMAP_PROFILES: ProfileMeta[] = [
  {
    id: "discovery",
    label: "Descubrimiento",
    short: "Hosts vivos",
    args: "-sn -R",
    duration: "rápido",
    icon: "◎",
    useCase: "Inventario inicial, ping sweep + reverse DNS",
  },
  {
    id: "quick",
    label: "Rápido",
    short: "Top 100 puertos",
    args: "-T4 -F",
    duration: "rápido",
    icon: "⚡",
    useCase: "Triaje express de servicios expuestos",
  },
  {
    id: "standard",
    label: "Estándar",
    short: "Servicios + scripts",
    args: "-T4 -sV -sC --version-light",
    duration: "medio",
    icon: "◈",
    useCase: "Auditoría habitual — versión y banner",
  },
  {
    id: "full",
    label: "Completo",
    short: "Todos los puertos",
    args: "-T4 -sV -sC -p-",
    duration: "muy lento",
    icon: "▣",
    useCase: "Pentest / hardening — escaneo exhaustivo",
  },
  {
    id: "stealth",
    label: "Sigiloso",
    short: "SYN scan",
    args: "-T2 -sS -F",
    duration: "medio",
    icon: "◌",
    useCase: "Evitar IDS — SYN half-open",
  },
  {
    id: "vulnerabilities",
    label: "CVE / vuln",
    short: "NSE vuln",
    args: "-T4 -sV --script vuln",
    duration: "lento",
    icon: "⚠",
    useCase: "Detección CVE con scripts NSE",
  },
  {
    id: "custom",
    label: "Personalizado",
    short: "Args libres",
    args: "(custom)",
    duration: "medio",
    icon: "⌘",
    useCase: "Perfil avanzado — flags nmap manuales",
  },
];

export function buildCommandPreview(
  profile: ScanProfile,
  targets: string,
  customArgs?: string,
  scanCves?: boolean,
): string {
  const meta = NMAP_PROFILES.find((p) => p.id === profile);
  let args = meta?.args ?? "-sn";
  if (profile === "custom" && customArgs?.trim()) {
    args = customArgs.trim();
  } else if (scanCves && profile !== "vulnerabilities" && profile !== "custom") {
    args = `${args} --script vuln`;
  }
  const t = targets.trim() || "<objetivos>";
  return `nmap ${args} --host-timeout 5s -oX - ${t}`;
}
