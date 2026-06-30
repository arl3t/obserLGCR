/**
 * ReportIframeModal.tsx — muestra el informe del caso (HTML) en un iframe
 * SANDBOXED (sin scripts, sin same-origin) → neutraliza cualquier XSS aunque el
 * informe traiga datos del caso controlados por el atacante. Reusado por la
 * vista de Investigación y por la de Tickets.
 */
import { X } from "lucide-react";

export function ReportIframeModal({ html, title = "Informe del incidente", onClose }: {
  html: string; title?: string; onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="flex h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <span className="text-sm font-medium text-slate-800">{title}</span>
          <button className="rounded p-1 text-slate-500 hover:bg-slate-100" onClick={onClose}><X className="h-4 w-4" /></button>
        </div>
        <iframe sandbox="" title={title} srcDoc={html} className="w-full flex-1 border-0" />
      </div>
    </div>
  );
}
