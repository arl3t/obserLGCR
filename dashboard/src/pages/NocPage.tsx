import { PageHeader } from "@/components/layout/PageHeader";
import { NocDashboard } from "@/components/noc/NocDashboard";
import { NocDeviceDetail } from "@/components/noc/NocDeviceDetail";

/** Hub NOC — activos registrados, monitoreo e inventario/gobernanza por activo. */
export function NocPage() {
  return (
    <>
      <PageHeader
        title="Centro de operaciones NOC"
        subtitle="Activos registrados · monitoreo en tiempo real · inventario y gobernanza por dispositivo"
      />
      <NocDashboard />
    </>
  );
}

export function NocDeviceDetailPage() {
  return <NocDeviceDetail />;
}
