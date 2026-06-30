/**
 * GeoOriginCard — ubica geográficamente la IP pública de ORIGEN del caso.
 * Resuelve la IP pública (ioc_value si es IP pública, o el primer IOC tipo ip
 * público de la lista), pide país/ciudad/ASN/coordenadas a /api/geoip/batch y
 * las muestra junto a un mapa mundial compacto (GeoOriginMap). Las IPs privadas
 * (RFC1918 / este-oeste) no tienen origen geográfico → la tarjeta no se renderiza.
 */
import { useMemo } from "react";
import { Globe } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useGeoIpBatch } from "@/hooks/useGeoIpBatch";
import { classifyIp } from "@/lib/geoip";
import { GeoOriginMap } from "@/components/geo/GeoOriginMap";
import type { FullCase } from "./useCaseInvestigation";

export function GeoOriginCard({ c }: { c: FullCase }) {
  const publicIp = useMemo<string | null>(() => {
    if (c.ioc_value && /^ip$/i.test(c.ioc_type ?? "") && classifyIp(c.ioc_value).source === "public") {
      return c.ioc_value;
    }
    const ipIoc = c.iocs?.find(
      (i) => /^ip$/i.test(i.ioc_type) && classifyIp(i.ioc_value).source === "public",
    );
    return ipIoc?.ioc_value ?? null;
  }, [c.ioc_value, c.ioc_type, c.iocs]);

  const { byIp, pending } = useGeoIpBatch(publicIp ? [publicIp] : []);
  const geo = publicIp ? byIp[publicIp] : null;

  // Sin IP pública de origen (caso interno / este-oeste) no hay geo que mostrar.
  if (!publicIp) return null;

  const hasCoords = geo?.lat != null && geo?.lon != null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <Globe className="h-3.5 w-3.5" />
          Origen geográfico
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <GeoOriginMap lat={geo?.lat} lon={geo?.lon} />

        <div className="flex items-center gap-2 text-xs">
          {geo?.flagUrl && (
            <img src={geo.flagUrl} alt={geo.countryCode ?? ""} className="h-3 w-4 shrink-0 rounded-sm" />
          )}
          <span className="font-medium text-foreground">
            {geo?.countryName ?? (pending ? "Resolviendo…" : "País desconocido")}
          </span>
          {geo?.city && <span className="text-muted-foreground">· {geo.city}</span>}
        </div>

        <div className="font-mono text-[10px] text-muted-foreground break-all">{publicIp}</div>
        {geo?.asn && <div className="text-[10px] text-muted-foreground">{geo.asn}</div>}
        {hasCoords && (
          <div className="text-[10px] text-muted-foreground">
            {(geo!.lat as number).toFixed(2)}, {(geo!.lon as number).toFixed(2)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
