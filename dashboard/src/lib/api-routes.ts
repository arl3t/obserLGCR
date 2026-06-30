/** Rutas previstas para backend (Nginx → proxy). El front puede llamarlas cuando exista el API. */

export const API_ROUTES = {
  trinoStatement: "/api/trino/v1/statement",
  pcapAnalyze: "/api/pcap/analyze",
  shadowserverUpload: "/api/shadowserver/upload",
  leakIntelUpload: "/api/leak-intel/upload",
  shodanDomainSearch: "/api/shodan/domain-search",
  thcReverseDns: "/api/intel/thc-reverse-dns",
} as const;
