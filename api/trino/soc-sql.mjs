/**
 * Lecturas sobre tablas materializadas por scripts SOC MITRE (`scripts/run-soc-mitre-hunts.sh`).
 * Requiere ejecutar el runner antes; si la tabla no existe, Trino devolverá error.
 */
export function createSocSql(catalog, schema) {
  const fq = (name) => `${catalog}.${schema}.${name}`;

  return {
    /** @param {number} limit */
    iocPortScannersPreview(limit) {
      return `
SELECT * FROM ${fq("ioc_port_scanners")}
ORDER BY ports_scanned DESC
LIMIT ${limit}
`.trim();
    },
    iocInitialAccessPreview(limit) {
      return `
SELECT * FROM ${fq("ioc_initial_access_attempts")}
ORDER BY attempts DESC
LIMIT ${limit}
`.trim();
    },
    iocPersistentPreview(limit) {
      return `
SELECT * FROM ${fq("ioc_persistent_connections")}
ORDER BY total_connections DESC
LIMIT ${limit}
`.trim();
    },
    iocUdpPreview(limit) {
      return `
SELECT * FROM ${fq("ioc_defense_evasion_udp")}
ORDER BY udp_events DESC
LIMIT ${limit}
`.trim();
    },
    iocCredentialStuffingPreview(limit) {
      return `
SELECT * FROM ${fq("ioc_credential_stuffing")}
ORDER BY correlation_hits DESC
LIMIT ${limit}
`.trim();
    },
    iocLateralMovementPreview(limit) {
      return `
SELECT * FROM ${fq("ioc_lateral_movement")}
ORDER BY attempts DESC
LIMIT ${limit}
`.trim();
    },
  };
}
