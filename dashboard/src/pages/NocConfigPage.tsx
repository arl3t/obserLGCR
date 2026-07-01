import { Link } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { AgentDownloadPanel } from "@/components/noc/AgentDownloadPanel";
import { NocGlobalPolicies } from "@/components/noc/NocGlobalPolicies";

export function NocConfigPage() {
  return (
    <>
      <PageHeader
        title="Configuración NOC"
        subtitle="Agentes de monitoreo · gobernanza de software · políticas globales"
      />
      <div className="px-6 pb-6 space-y-4">
        <Link to="/noc" className="ut-header__back">
          ← Volver al centro NOC
        </Link>
        <AgentDownloadPanel />
        <NocGlobalPolicies defaultOpen />
      </div>
    </>
  );
}
