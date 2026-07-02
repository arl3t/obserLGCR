import {
  Boxes,
  Cpu,
  HardDrive,
  Laptop,
  Network,
  Printer,
  Router,
  Server,
  Shield,
  Smartphone,
  Wifi,
  type LucideIcon,
} from "lucide-react";

export interface DeviceFamily {
  id: string;
  label: string;
  icon: LucideIcon;
  accent: string;
}

export const DEVICE_FAMILIES: DeviceFamily[] = [
  { id: "server", label: "Servidores", icon: Server, accent: "#22d3ee" },
  { id: "router", label: "Routers", icon: Router, accent: "#a78bfa" },
  { id: "switch", label: "Switches", icon: Network, accent: "#34d399" },
  { id: "firewall", label: "Firewalls", icon: Shield, accent: "#f87171" },
  { id: "workstation", label: "Estaciones", icon: Laptop, accent: "#60a5fa" },
  { id: "access_point", label: "Access Points", icon: Wifi, accent: "#fbbf24" },
  { id: "printer", label: "Impresoras", icon: Printer, accent: "#f472b6" },
  { id: "storage", label: "Almacenamiento", icon: HardDrive, accent: "#2dd4bf" },
  { id: "iot", label: "IoT / OT", icon: Cpu, accent: "#c084fc" },
  { id: "mobile", label: "Móviles", icon: Smartphone, accent: "#38bdf8" },
  { id: "other", label: "Otros", icon: Boxes, accent: "#94a3b8" },
];

export const DEVICE_TYPE_OPTIONS = DEVICE_FAMILIES.map((f) => f.id);

const FAMILY_BY_ID = new Map(DEVICE_FAMILIES.map((f) => [f.id, f]));

export function familyFor(deviceType: string | null | undefined): DeviceFamily {
  const key = (deviceType || "other").toLowerCase();
  return FAMILY_BY_ID.get(key) ?? FAMILY_BY_ID.get("other")!;
}
