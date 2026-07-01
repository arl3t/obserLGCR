import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ExternalLink, Network } from "lucide-react";
import { fetchUnifiedAssets, type UnifiedAsset } from "@/api/unifiedAssets";

interface DeviceNetworkIdentityProps {
  nocDeviceId: string;
  hostname: string;
  ipAddress: string | null;
}

export function DeviceNetworkIdentity({
  nocDeviceId,
  hostname,
  ipAddress,
}: DeviceNetworkIdentityProps) {
  const [asset, setAsset] = useState<UnifiedAsset | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const search = hostname || ipAddress?.replace(/\/32$/, "") || "";
        const page = await fetchUnifiedAssets({ search, limit: 50 });
        const match =
          page.data.find((a) => a.noc_device_id === nocDeviceId) ??
          page.data.find(
            (a) =>
              a.hostname === hostname ||
              (ipAddress && a.ip_address?.startsWith(ipAddress.replace(/\/32$/, ""))),
          ) ??
          null;
        if (!cancelled) setAsset(match);
      } catch {
        if (!cancelled) setAsset(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [nocDeviceId, hostname, ipAddress]);

  const meta = asset?.discovery_meta as Record<string, unknown> | null;
  const osGuess =
    asset?.os_guess ?? (typeof meta?.os_guess === "string" ? meta.os_guess : null);

  return (
    <section className="ut-card">
      <div className="ut-chart-head">
        <h3 className="ut-chart-head__title">
          <Network size={16} className="inline mr-1" aria-hidden />
          Identidad de red
        </h3>
        <Link
          to={`/detection?tab=assets`}
          className="ut-table__link text-[12px]"
        >
          Ver en Activos <ExternalLink size={12} className="inline" />
        </Link>
      </div>

      {loading ? (
        <p className="ut-sidebar__text">Cargando contexto IPAM/discovery…</p>
      ) : !asset ? (
        <p className="ut-sidebar__text">
          Sin vínculo IPAM o descubrimiento. Ejecute un escaneo en Detección → Descubrimiento con sync IPAM.
        </p>
      ) : (
        <dl className="noc-identity-grid">
          <div>
            <dt>Región IPAM</dt>
            <dd>{asset.region_name ?? "—"}</dd>
          </div>
          <div>
            <dt>Subred</dt>
            <dd>{asset.cidr_block ?? "—"}</dd>
          </div>
          <div>
            <dt>Estado IPAM</dt>
            <dd>{asset.ipam_status ?? "—"}</dd>
          </div>
          <div>
            <dt>MAC</dt>
            <dd>{asset.mac_address ?? "—"}</dd>
          </div>
          <div>
            <dt>OS (discovery)</dt>
            <dd>{osGuess ?? "—"}</dd>
          </div>
          <div>
            <dt>Puertos abiertos</dt>
            <dd>{asset.discovery_open_ports ?? 0}</dd>
          </div>
          <div>
            <dt>Registry SOC</dt>
            <dd>
              {asset.registry_sensor_key
                ? `${asset.registry_type ?? "activo"} · ${asset.criticality ?? "—"}`
                : "—"}
            </dd>
          </div>
          <div>
            <dt>Link IPAM↔NOC</dt>
            <dd>{asset.ipam_linked ? "Vinculado" : "Pendiente"}</dd>
          </div>
        </dl>
      )}
    </section>
  );
}
