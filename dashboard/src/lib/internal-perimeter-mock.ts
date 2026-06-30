/**
 * Datos de laboratorio para Overview → perímetro interno (OPNsense/syslog, Wazuh, remitentes).
 * Activar con VITE_INTERNAL_PERIMETER_MOCK=1 en legacyhunt-dashboard/.env (no afecta vigilancia digital).
 * UI alineada al comportamiento del commit #demo (1a8e3c0b): useTrinoSql + estas cifras sustituyen Trino.
 */
export function isInternalPerimeterMock(): boolean {
  const v = import.meta.env.VITE_INTERNAL_PERIMETER_MOCK;
  return v === "true" || v === "1";
}

export const INTERNAL_PERIMETER_MOCK = {
  filterlogEvents24h: 12_480,
  blocks24h: 4_203,
  diag168h: 982_000,
  wazuhAlerts24h: 156,
  senders: [
    { source_ip: "203.0.113.10", c: 8_900 },
    { source_ip: "198.51.100.2", c: 120 },
    { source_ip: "192.0.2.55", c: 44 },
  ],
} as const;
