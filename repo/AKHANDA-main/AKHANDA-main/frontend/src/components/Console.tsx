import { useState } from "react";
import { CLEAN_CHAIN, CHAIN_ID, OPERATOR_KEY_ID, CONCUR_KEY_ID, COSIGNED_COUNT, type ChainEntry } from "../data/chainData";
import Hash from "./Hash";

/**
 * The chain identifier, both key ids and the terminal hash are read from the generated
 * ledger data. They used to be typed into this file, and the terminal hash that was
 * typed in, "f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8", was 32 characters long. A SHA-256 is
 * 64. Anyone who counted would have known the screen was decorated rather than computed.
 */

const STATUS_CONFIG = {
  verified: {
    label: "VERIFIED",
    dot: "bg-green-400",
    glow: "#22c55e",
    bar: "bg-green-500/20 border-green-500/30",
    text: "text-green-400",
    badge: "bg-green-500/10 text-green-400 border-green-500/30",
    rowClass: "chain-status-green",
  },
  "in-progress": {
    label: "IN PROGRESS",
    dot: "bg-amber-400",
    glow: "#f59e0b",
    bar: "bg-amber-500/10 border-amber-500/20",
    text: "text-amber-400",
    badge: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    rowClass: "chain-status-amber",
  },
  tampered: {
    label: "TAMPERED",
    dot: "bg-red-500",
    glow: "#ef4444",
    bar: "bg-red-500/10 border-red-500/30",
    text: "text-red-400",
    badge: "bg-red-500/10 text-red-400 border-red-500/30",
    rowClass: "",
  },
};

function formatTs(ts: string) {
  const d = new Date(ts);
  return (
    d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false,
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }) + " IST"
  );
}

function HashDisplay({ hash, label }: { hash: string; label: string }) {
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="text-slate-600 text-[10px] font-mono uppercase tracking-widest">{label}</span>
      <span className="text-[10px] text-slate-400 min-w-0">
        <Hash value={hash} />
      </span>
    </div>
  );
}

function EntryRow({
  entry,
  index,
  expanded,
  onToggle,
}: {
  entry: ChainEntry;
  index: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  const cfg = STATUS_CONFIG[entry.status];

  return (
    <div className={`${cfg.rowClass} animate-fade-in-up`} style={{ animationDelay: `${index * 60}ms` }}>
      <div className="flex">
        {/* Narrower rail on a phone so the card keeps its width */}
        <div className="flex flex-col items-center w-6 sm:w-10 shrink-0">
          <div
            className={`status-dot w-3 h-3 rounded-full ${cfg.dot} shrink-0 mt-5`}
            style={{ boxShadow: `0 0 8px ${cfg.glow}` }}
          />
          <div className="w-px flex-1 mt-1" style={{ background: "rgba(255,255,255,0.06)" }} />
        </div>

        <div
          className={`flex-1 min-w-0 ml-2 sm:ml-3 mb-2 border rounded cursor-pointer transition-all hover:border-blue-500/30 ${cfg.bar}`}
          onClick={onToggle}
        >
          {/* Timestamp block drops below the title on a phone instead of squeezing it */}
          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 sm:gap-4 px-4 sm:px-5 py-4">
            <div className="flex flex-col gap-1 min-w-0">
              <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
                <span className="font-mono text-xs text-blue-300 font-medium">{entry.seq}</span>
                <span
                  className={`text-[10px] font-mono font-semibold tracking-widest border rounded-sm px-2 py-0.5 ${cfg.badge}`}
                >
                  {cfg.label}
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {entry.witnessApproval === "APPROVED"
                    ? "🔒 Co-signed"
                    : "○ Operator only"}
                </span>
              </div>
              <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
                <span className="text-xs font-semibold text-white tracking-wide">
                  {entry.action.replace(/_/g, " ")}
                </span>
                <span className="text-slate-500 text-[11px]">·</span>
                <span className="text-slate-400 text-[11px]">{entry.custodyTier}</span>
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">{entry.details}</p>
            </div>
            <div className="sm:text-right shrink-0">
              <div className="text-[10px] font-mono text-slate-500">{formatTs(entry.timestamp)}</div>
              <div className="text-[10px] font-mono text-slate-600 mt-0.5 break-all">
                {entry.witnessNode}
              </div>
              <div className="text-[10px] text-slate-600 mt-1 sm:mt-2">{expanded ? "▲" : "▼"}</div>
            </div>
          </div>

          {expanded && (
            <div className="border-t border-white/5 px-4 sm:px-5 py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <HashDisplay hash={entry.hash} label="Entry hash" />
              <HashDisplay hash={entry.prevHash} label="Previous hash" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Console() {
  const [expanded, setExpanded] = useState<number | null>(null);
  const verified = CLEAN_CHAIN.filter((e) => e.status === "verified").length;
  const terminal = CLEAN_CHAIN[CLEAN_CHAIN.length - 1];

  return (
    <div className="min-h-screen overflow-x-hidden" style={{ background: "#060c18" }}>
      <div className="border-b border-white/5 px-5 sm:px-8 py-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-white font-semibold tracking-wide">Chain Console</span>
            <span className="text-xs font-mono text-slate-500 break-all">Chain {CHAIN_ID}</span>
          </div>
          <div className="text-[10px] sm:text-[11px] font-mono text-slate-600 mt-0.5 break-all">
            Flash Memory · operator key {OPERATOR_KEY_ID}
            {CONCUR_KEY_ID ? ` · co-signer key ${CONCUR_KEY_ID}` : " · no co-signer on this chain"}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4 sm:gap-6">
          <div>
            <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">
              Chain integrity
            </div>
            <div className="text-green-400 font-mono font-semibold text-sm">
              {verified}/{CLEAN_CHAIN.length} VERIFIED
            </div>
          </div>
          <div className="hidden sm:block w-px h-8 bg-white/5" />
          <div>
            <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">
              Dual-signed
            </div>
            <div className="text-slate-300 font-mono font-semibold text-sm">
              {COSIGNED_COUNT}/{CLEAN_CHAIN.length}
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-6 sm:py-8">
        <div>
          {CLEAN_CHAIN.map((entry, i) => (
            <EntryRow
              key={entry.id}
              entry={entry}
              index={i}
              expanded={expanded === entry.id}
              onToggle={() => setExpanded(expanded === entry.id ? null : entry.id)}
            />
          ))}
        </div>

        <div
          className="mt-4 ml-6 sm:ml-10 border border-green-500/20 rounded px-4 sm:px-5 py-4"
          style={{ background: "rgba(34,197,94,0.04)" }}
        >
          <div className="flex items-center gap-3">
            <div
              className="w-3 h-3 rounded-full bg-green-400 shrink-0"
              style={{ boxShadow: "0 0 8px #22c55e" }}
            />
            <span className="text-green-400 text-[11px] sm:text-xs font-mono font-semibold tracking-widest uppercase">
              Chain sealed, all entries verified
            </span>
          </div>
          <div className="mt-2 text-slate-500 text-[11px] font-mono min-w-0">
            Terminal hash: <Hash value={terminal.hash} className="text-slate-400" />
          </div>
          <div className="mt-2 text-slate-600 text-[10px] font-mono leading-relaxed">
            {COSIGNED_COUNT} of {CLEAN_CHAIN.length} entries carry a second signature. The rest were
            signed by the operator alone and are shown as such.
          </div>
        </div>
      </div>
    </div>
  );
}
