export function AgentDownloadPanel() {
  const agents = [
    {
      os: "Linux",
      file: "/agents/obserlgcr-noc-agent-linux.sh",
      name: "obserlgcr-noc-agent-linux.sh",
      setup: "chmod +x … && sudo ./obserlgcr-noc-agent-linux.sh --setup",
    },
    {
      os: "macOS",
      file: "/agents/obserlgcr-noc-agent-macos.sh",
      name: "obserlgcr-noc-agent-macos.sh",
      setup: "chmod +x … && ./obserlgcr-noc-agent-macos.sh --setup",
    },
    {
      os: "Windows",
      file: "/agents/obserlgcr-noc-agent-windows.ps1",
      name: "obserlgcr-noc-agent-windows.ps1",
      setup: "powershell -ExecutionPolicy Bypass -File .\\… -Setup",
    },
  ];

  return (
    <section id="noc-agents" className="ut-card" aria-labelledby="agents-title">
      <h2 id="agents-title" className="ut-chart-head__title">
        Instalación del agente
      </h2>
      <p className="ut-sidebar__text" style={{ marginBottom: "1rem" }}>
        Heartbeat cada 5 min · credencial lab: <code>noc-agent@obserlgcr.local</code>
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {agents.map((a) => (
          <div key={a.os} className="rounded border border-[var(--ut-border-subtle)] p-3">
            <p className="ut-sidebar__title" style={{ marginBottom: "0.35rem" }}>
              {a.os}
            </p>
            <a href={a.file} download={a.name} className="ut-btn ut-btn--sm" style={{ width: "100%" }}>
              Descargar
            </a>
            <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-[10px] text-emerald-400">
              {a.setup}
            </pre>
          </div>
        ))}
      </div>
    </section>
  );
}
