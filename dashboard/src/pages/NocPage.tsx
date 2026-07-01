import { PageHeader } from "@/components/layout/PageHeader";
import { NocDashboard } from "@/components/noc/NocDashboard";
import { NocDeviceDetail } from "@/components/noc/NocDeviceDetail";

/** Hub NOC — activos registrados, monitoreo e inventario/gobernanza por activo. */
export function NocPage() {
  return (
    <>
      <PageHeader
        title="Centro NOC — Monitoreo de infraestructura"
        subtitle="Wallboard operativo · activos · alertas · sitios · salud por activo"
      />
      <NocDashboard />
    </>
  );
}

export function NocDeviceDetailPage() {
  return <NocDeviceDetail />;
}
