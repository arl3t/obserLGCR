import { Link } from "react-router-dom";
import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  backTo?: { label: string; href: string };
}

/** Cabecera de página alineada al diseño uptime monitor. */
export function PageHeader({ title, subtitle, actions, backTo }: PageHeaderProps) {
  return (
    <div className="ut-toolbar">
      <header className="ut-header" style={{ marginBottom: 0 }}>
        {backTo && (
          <Link to={backTo.href} className="ut-header__back">
            {backTo.label}
          </Link>
        )}
        <h1 className="ut-header__title">{title}</h1>
        {subtitle && <p className="ut-header__subtitle">{subtitle}</p>}
      </header>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
