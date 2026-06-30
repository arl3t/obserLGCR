export type ShodanFacetBucket = {
  count: number;
  value: string | number;
};

export type ShodanDomainSearchResponse = {
  ok: true;
  domain: string;
  shodanQuery: string;
  total: number;
  facets: Record<string, ShodanFacetBucket[]>;
  matches: ShodanHostMatch[];
  truncated: boolean;
  shodanWebUrl: string;
};

export type ShodanHostMatch = {
  ip: string | null;
  hostnames: string[];
  org: string | null;
  isp: string | null;
  country: string | null;
  countryCode: string | null;
  city: string | null;
  port: number | null;
  transport: string | null;
  product: string | null;
  timestamp: string | null;
  ssl: { cn: string | null } | null;
  banner: string;
};

export type ShodanErrorResponse = {
  ok: false;
  error: string;
};
