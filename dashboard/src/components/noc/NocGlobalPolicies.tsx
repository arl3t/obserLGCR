import { useState } from "react";
import { ChevronDown, ShieldAlert } from "lucide-react";
import { GovernancePanel } from "@/components/noc/governance/GovernancePanel";

/** Políticas globales de software (listas BL/WL) — colapsable en el hub NOC. */
export function NocGlobalPolicies() {
  const [open, setOpen] = useState(false);

  return (
    <section className="noc-collapse" style={{ marginTop: "1.25rem" }}>
      <button
        type="button"
        className="noc-collapse__head"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem" }}>
          <ShieldAlert size={16} aria-hidden />
          Políticas globales de software
        </span>
        <ChevronDown size={16} className={open ? "rotate-180" : ""} aria-hidden />
      </button>
      {open && (
        <div className="noc-collapse__body">
          <GovernancePanel embedded />
        </div>
      )}
    </section>
  );
}
