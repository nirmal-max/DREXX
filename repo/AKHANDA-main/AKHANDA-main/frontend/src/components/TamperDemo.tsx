import { useEffect, useState } from "react";
import { CLEAN_CHAIN, CHAIN_ID, type ChainEntry } from "../data/chainData";
import { verifyChain, type ChainResult } from "../lib/verify";

/**
 * A real check, not a simulation.
 *
 * Nothing on this screen is pre-labelled and nothing runs on a timer. Pressing
 * "Inject Tamper" edits one signed field in memory, then the browser rebuilds every
 * entry from its sixteen signed fields and hashes it with the platform's own SHA-256.
 * Rows turn red because the arithmetic disagrees, not because a flag was set.
 *
 * Every run is printed to the developer console so a sceptic can watch it happen.
 */

const STATUS = {
  ok: {
    label: "VERIFIED",
    dot: "bg-green-400",
    glow: "#22c55e",
    border: "border-green-500/20",
    bg: "bg-green-500/5",
    badge: "bg-green-500/10 text-green-400 border-green-500/30",
  },
  bad: {
    label: "BROKEN",
    dot: "bg-red-500",
    glow: "#ef4444",
    border: "border-red-500/40",
    bg: "animate-tamper-flash",
    badge: "bg-red-500/10 text-red-400 border-red-500/30",
  },
};

type Row = { entry: ChainEntry; recomputed: string; problems: string[] };

function DemoRow({ row, index }: { row: Row; index: number }) {
  const broken = row.problems.length > 0;
  const cfg = broken ? STATUS.bad : STATUS.ok;
  const { entry } = row;

  return (
    <div
      className={`flex items-start gap-3 py-3 px-4 rounded border transition-all duration-500 ${cfg.border} ${cfg.bg}`}
      style={{ animationDelay: `${index * 40}ms` }}
    >
      <div className="flex items-center h-full pt-0.5">
        <div
          className={`w-2.5 h-2.5 rounded-full ${cfg.dot} shrink-0 mt-1`}
          style={{ boxShadow: `0 0 8px ${cfg.glow}` }}
        />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="font-mono text-[10px] text-blue-300">{entry.seq}</span>
          <span
            className={`text-[9px] font-mono font-semibold tracking-widest border rounded-sm px-1.5 py-0.5 ${cfg.badge}`}
          >
            {cfg.label}
          </span>
          {broken && (
            <span className="text-[9px] font-mono text-red-400/80 animate-pulse">
              &#9888; {row.problems[0]}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 mt-0.5 flex-wrap">
          <span className="text-xs font-semibold text-slate-200">
            {entry.action.replace(/_/g, " ")}
          </span>
          <span className="text-slate-600 text-[10px]">&middot;</span>
          <span className="text-slate-500 text-[10px]">{entry.custodyTier}</span>
          <span className="text-slate-600 text-[10px]">&middot;</span>
          <span className="text-slate-500 text-[10px]">{entry.outcome}</span>
        </div>

        {/* The evidence: what the ledger recorded, and what this browser just computed. */}
        <div className="mt-1.5 text-[10px] font-mono leading-relaxed border-l-2 pl-2 border-slate-700 break-all">
          <div className="text-slate-500">
            recorded&nbsp;&nbsp;&nbsp;<span className="text-slate-400">{entry.hash}</span>
          </div>
          <div className={broken ? "text-red-400" : "text-green-400/80"}>
            recomputed&nbsp;<span>{row.recomputed}</span>
          </div>
        </div>
      </div>

      <div className="shrink-0 text-right hidden md:block">
        <div className="font-mono text-[9px] text-slate-600">{entry.witnessApproval}</div>
      </div>
    </div>
  );
}

export default function TamperDemo() {
  const [chain, setChain] = useState<ChainEntry[]>(CLEAN_CHAIN);
  const [result, setResult] = useState<ChainResult | null>(null);
  const [running, setRunning] = useState(false);
  const [tampered, setTampered] = useState(false);

  const run = async (entries: ChainEntry[]) => {
    setRunning(true);
    const r = await verifyChain(entries);
    console.table(
      r.rows.map((x) => ({
        seq: x.seq,
        recorded: x.recorded,
        recomputed: x.recomputed,
        matches: x.hashOk,
      })),
    );
    setResult(r);
    setRunning(false);
  };

  useEffect(() => {
    void run(CLEAN_CHAIN);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** Edit one signed field in memory. The file on disk is never touched. */
  const injectTamper = async () => {
    if (running || tampered) return;
    const next = CLEAN_CHAIN.map((e, i) =>
      i === 1 ? { ...e, raw: { ...e.raw, target_ref: e.raw.target_ref + "-ALTERED" } } : { ...e },
    );
    setChain(next);
    setTampered(true);
    await run(next);
  };

  const reset = async () => {
    setChain(CLEAN_CHAIN);
    setTampered(false);
    await run(CLEAN_CHAIN);
  };

  const rows: Row[] =
    result?.rows.map((r, i) => ({
      entry: chain[i],
      recomputed: r.recomputed,
      problems: r.problems,
    })) ?? [];
  const brokenCount = rows.filter((r) => r.problems.length > 0).length;

  return (
    <div className="min-h-screen overflow-x-hidden" style={{ background: "#060c18" }}>
      <div className="border-b border-white/5 px-5 sm:px-8 py-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <span className="text-white font-semibold tracking-wide">Live integrity check</span>
            <div className="text-[10px] sm:text-[11px] font-mono text-slate-600 mt-0.5 break-all">
              Chain {CHAIN_ID} &middot; every hash recomputed in this browser, not fetched
              from a server
            </div>
          </div>
          {result && !result.ok && (
            <div
              className="flex items-center gap-2 px-4 py-2 rounded border border-red-500/30"
              style={{ background: "rgba(239,68,68,0.08)" }}
            >
              <span className="text-red-400 text-sm">&#9888;</span>
              <span className="text-red-400 text-xs font-mono font-semibold tracking-widest uppercase">
                broken at sequence {result.brokenSeq}
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-4 sm:px-6 py-6 sm:py-8 grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8">
        <div className="lg:col-span-1 space-y-6">
          <div className="rounded border border-white/6 p-5" style={{ background: "#0a1020" }}>
            <div className="text-[10px] font-mono text-blue-400/70 uppercase tracking-widest mb-4">
              What actually happens
            </div>
            <ol className="space-y-3 text-[11px] text-slate-400 leading-relaxed list-none">
              <li className="flex gap-2">
                <span className="text-blue-400 font-mono shrink-0">01</span> Each entry is
                rebuilt from its sixteen signed fields, each prefixed with its length so no
                two records can share signing bytes.
              </li>
              <li className="flex gap-2">
                <span className="text-blue-400 font-mono shrink-0">02</span> The browser
                hashes those bytes with SHA-256 and compares against the recorded value.
              </li>
              <li className="flex gap-2">
                <span className="text-blue-400 font-mono shrink-0">03</span> Press the button
                and one signed field of entry 1 is edited in memory.
              </li>
              <li className="flex gap-2">
                <span className="text-blue-400 font-mono shrink-0">04</span> Everything is
                recomputed. That entry no longer matches, and each later entry, which commits
                to the hash before it, fails too.
              </li>
              <li className="flex gap-2">
                <span className="text-blue-400 font-mono shrink-0">05</span> Open the
                developer console to see every recorded and recomputed hash printed.
              </li>
            </ol>
          </div>

          <div className="rounded border border-white/6 p-5 space-y-4" style={{ background: "#0a1020" }}>
            <div className="text-[10px] font-mono text-blue-400/70 uppercase tracking-widest">
              Controls
            </div>

            <button
              onClick={() => void injectTamper()}
              disabled={tampered || running}
              className="w-full py-3 rounded border text-xs font-mono font-semibold tracking-widest uppercase transition-all active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                background: tampered || running ? "rgba(239,68,68,0.05)" : "rgba(239,68,68,0.12)",
                borderColor: "rgba(239,68,68,0.4)",
                color: "#f87171",
                boxShadow: tampered || running ? "none" : "0 0 16px rgba(239,68,68,0.2)",
              }}
            >
              {running ? "Recomputing…" : tampered ? "Tamper Applied" : "Inject Tamper"}
            </button>

            <button
              onClick={() => void reset()}
              disabled={!tampered || running}
              className="w-full py-3 rounded border border-green-500/30 text-green-400 text-xs font-mono font-semibold tracking-widest uppercase hover:bg-green-500/10 transition-all active:scale-95 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Restore Original
            </button>

            {result && !result.ok && (
              <div className="text-[10px] font-mono text-red-400/70 leading-relaxed pt-2 border-t border-white/5">
                Verification failed at sequence {result.brokenSeq}.<br />
                {brokenCount} of {result.rows.length} entries no longer verify.
              </div>
            )}
            {result && result.ok && !running && (
              <div className="text-[10px] font-mono text-green-400/50 leading-relaxed pt-2 border-t border-white/5">
                Chain integrity: INTACT<br />
                {result.rows.length} hashes recomputed in {result.elapsedMs.toFixed(1)} ms.
              </div>
            )}
            <div className="text-[10px] font-mono text-slate-600 leading-relaxed pt-2 border-t border-white/5">
              Alters one field in memory only. The ledger file on disk is never modified.
            </div>
          </div>
        </div>

        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
              Chain entries &mdash; recomputed live
            </span>
            <div className="flex items-center gap-4 text-[10px] font-mono text-slate-600">
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" /> Verified
              </span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" /> Broken
              </span>
            </div>
          </div>

          <div className="space-y-2">
            {rows.map((r, i) => (
              <DemoRow key={r.entry.id} row={r} index={i} />
            ))}
          </div>

          {result && !result.ok && (
            <div
              className="mt-6 p-4 rounded border border-red-500/30"
              style={{ background: "rgba(239,68,68,0.06)" }}
            >
              <div className="text-red-400 text-xs font-mono font-semibold mb-1">
                VERIFICATION REPORT
              </div>
              <div className="text-[11px] font-mono text-slate-400 space-y-0.5 break-all">
                <div>
                  Chain broken at sequence:{" "}
                  <span className="text-red-400">{result.brokenSeq}</span>
                </div>
                {result.rows
                  .filter((r) => r.problems.length)
                  .map((r) => (
                    <div key={r.seq}>
                      seq {r.seq}: <span className="text-red-400">{r.problems.join("; ")}</span>
                    </div>
                  ))}
                <div className="pt-1 text-slate-500">
                  Entries after the break also fail, because each commits to the hash of the
                  one before it. That cascade is arithmetic, not policy.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
