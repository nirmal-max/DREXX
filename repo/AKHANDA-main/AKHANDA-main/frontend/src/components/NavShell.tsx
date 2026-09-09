import type { ReactNode } from "react";

interface NavShellProps {
  page: string;
  onNavigate: (page: string) => void;
  children: ReactNode;
}

const NAV_ITEMS = [
  { id: "landing", label: "Home" },
  { id: "console", label: "Console" },
  { id: "certificate", label: "Certificate" },
  { id: "tamperdemo", label: "Tamper Demo" },
];

/**
 * Three fixed-width groups in one row overflowed a 375 px screen: the brand, four nav
 * buttons and the LIVE badge together are wider than the viewport, and the nav pushed
 * the page sideways on every screen below it.
 *
 * The brand and badge now share the top row, and the nav buttons sit on their own row
 * below, scrolling horizontally inside that row if they still do not fit. The bar
 * itself never widens the page.
 */
export default function NavShell({ page, onNavigate, children }: NavShellProps) {
  if (page === "landing") return <>{children}</>;

  return (
    <div className="min-h-screen flex flex-col overflow-x-hidden">
      <nav
        className="border-b border-white/5 px-4 sm:px-8 py-2.5 sm:py-3 sticky top-0 z-50"
        style={{ background: "rgba(6,12,24,0.95)", backdropFilter: "blur(12px)" }}
      >
        <div className="flex items-center justify-between gap-3">
          <button onClick={() => onNavigate("landing")} className="flex items-center gap-2.5 group shrink-0">
            <div
              className="w-7 h-7 rounded flex items-center justify-center shrink-0"
              style={{ background: "linear-gradient(135deg, #1c2e52, #3b82f6)" }}
            >
              <span className="text-white text-[10px] font-bold font-mono">Ak</span>
            </div>
            <span className="text-white font-bold tracking-widest text-xs uppercase group-hover:text-blue-300 transition-colors">
              AKHANDA
            </span>
          </button>

          {/* Tablet and up: nav sits inline */}
          <div className="hidden sm:flex items-center gap-1 min-w-0">
            {NAV_ITEMS.slice(1).map((item) => (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`px-3 lg:px-4 py-2 text-[11px] font-mono tracking-wider uppercase transition-colors rounded whitespace-nowrap ${
                  page === item.id ? "text-white bg-white/6" : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            <div
              className="w-1.5 h-1.5 rounded-full bg-green-400"
              style={{ boxShadow: "0 0 5px #22c55e" }}
            />
            <span className="text-[10px] font-mono text-slate-500">LIVE</span>
          </div>
        </div>

        {/* Phone: its own row, scrolling inside itself rather than widening the page */}
        <div className="sm:hidden -mx-4 px-4 mt-2 overflow-x-auto">
          <div className="flex items-center gap-1 w-max">
            {NAV_ITEMS.slice(1).map((item) => (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`px-3 py-1.5 text-[11px] font-mono tracking-wider uppercase transition-colors rounded whitespace-nowrap ${
                  page === item.id ? "text-white bg-white/6" : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      <div className="flex-1 min-w-0">{children}</div>
    </div>
  );
}
