export type ThcReverseDnsOk = {
  ok: true;
  ip: string;
  source: "lake" | "live";
  matching_records: number;
  domain_sample_count: number;
  domains: string[];
  query_ts?: string | null;
  has_more?: boolean;
  docUrl?: string;
};

export type ThcReverseDnsErr = {
  ok: false;
  error: string;
  ip?: string;
  domains?: string[];
  matching_records?: number;
  docUrl?: string;
};

export type ThcReverseDnsResponse = ThcReverseDnsOk | ThcReverseDnsErr;
