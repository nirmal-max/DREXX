import { CHAIN_ID, COSIGNED_COUNT, CLEAN_CHAIN } from "../data/chainData";

/**
 * Everything asserted on this page is either measured or attributed.
 *
 * An earlier version of this file carried an accreditation strip reading "CERT-IN
 * Empanelled · FSL-Approved · IEA 65B Compliant", a footer claiming "MHA EMPANELLED ·
 * ISO 17025", and a copyright line for a company that does not exist. None of that was
 * true. Claiming a Government of India empanelment we do not hold, to judges from NTRO,
 * is not a presentation risk, it is the end of the project. It is gone and it does not
 * come back.
 *
 * The strip now states what this actually is: a student prototype, and its version.
 */

interface LandingProps {
  onNavigate: (page: string) => void;
}

const FEATURES = [
  {
    title: "Linked-Hash Chain",
    body: "Each entry commits to the hash of the entry before it. Removing or altering one " +
      "breaks every entry after it, and the break names the sequence number where it happened.",
  },
  {
    title: "Independent Co-Signer",
    body: "A second machine holds a key this workstation has never seen and signs alongside it. " +
      "If that machine is unreachable the operation is refused, and the refusal is itself recorded.",
  },
  {
    title: "Mapped Certificate",
    body: "Output is mapped field by field to NIST SP 800-88 Rev. 2 and to the Bharatiya Sakshya " +
      "Adhiniyam 2023, s.63(4). The certificate states its own limits alongside its claims.",
  },
];

export default function Landing({ onNavigate }: LandingProps) {
  return (
    <div
      className="min-h-screen flex flex-col overflow-x-hidden"
      style={{ background: "linear-gradient(160deg, #060c18 0%, #0a1020 60%, #0f1a30 100%)" }}
    >
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(59,130,246,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.04) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />

      {/* Nav, stacks on a phone rather than overflowing */}
      <nav className="relative z-10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 px-5 sm:px-8 py-4 sm:py-5 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded flex items-center justify-center shrink-0"
            style={{ background: "linear-gradient(135deg, #1c2e52, #3b82f6)" }}
          >
            <span className="text-white text-xs font-bold font-mono">Ak</span>
          </div>
          <span className="text-white font-bold tracking-widest text-sm uppercase">AKHANDA</span>
          <span className="text-blue-400/60 text-xs font-mono ml-1">v0.1.0</span>
        </div>
        <div className="flex items-center gap-1 -ml-2 sm:ml-0">
          {["Console", "Certificate", "TamperDemo"].map((label) => (
            <button
              key={label}
              onClick={() => onNavigate(label.toLowerCase())}
              className="px-3 sm:px-4 py-2 text-[11px] sm:text-xs font-medium tracking-wider text-slate-400 hover:text-white transition-colors uppercase"
            >
              {label}
            </button>
          ))}
        </div>
      </nav>

      <main className="relative z-10 flex-1 flex flex-col items-center justify-center px-5 sm:px-8 py-14 sm:py-24 text-center">
        {/* What this is. Not what we wish it were. */}
        <div
          className="inline-flex flex-wrap items-center justify-center gap-2 mb-8 sm:mb-10 px-4 py-2 rounded-full border border-blue-500/30 max-w-full"
          style={{ background: "rgba(59,130,246,0.08)" }}
        >
          <div
            className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0"
            style={{ boxShadow: "0 0 6px #22c55e" }}
          />
          <span className="text-[10px] sm:text-xs font-mono text-blue-300 tracking-widest uppercase">
            Prototype v0.1.0 · SIH 2026 · SIH26149 · NTRO
          </span>
        </div>

        <h1
          className="text-4xl sm:text-5xl md:text-7xl font-bold text-white leading-none mb-5 sm:mb-6"
          style={{ letterSpacing: "-0.02em" }}
        >
          AKHANDA
        </h1>
        <p
          className="text-base sm:text-lg md:text-xl font-light text-slate-400 max-w-xl mb-3"
          style={{ letterSpacing: "0.06em" }}
        >
          अखण्ड, Unbroken. Indivisible. Complete.
        </p>
        <p className="text-[13px] sm:text-sm text-slate-500 max-w-2xl leading-relaxed mb-10 sm:mb-14">
          Secure erasure and file recovery, written into one append-only ledger where every entry
          is locked to the hash of the one before it. Operations that need a second party are
          refused when that party cannot be reached, and the refusal is recorded too.
        </p>

        <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center justify-center gap-3 sm:gap-4 mb-14 sm:mb-20 w-full sm:w-auto max-w-xs sm:max-w-none">
          <button
            onClick={() => onNavigate("console")}
            className="px-8 py-3.5 rounded text-sm font-semibold text-white tracking-wider uppercase transition-all hover:brightness-110 active:scale-95"
            style={{
              background: "linear-gradient(135deg, #1c2e52 0%, #3b82f6 100%)",
              boxShadow: "0 0 24px rgba(59,130,246,0.3)",
            }}
          >
            Open Console
          </button>
          <button
            onClick={() => onNavigate("tamperdemo")}
            className="px-8 py-3.5 rounded text-sm font-semibold text-red-400 border border-red-500/40 tracking-wider uppercase hover:bg-red-500/10 transition-all active:scale-95"
          >
            Run Tamper Demo
          </button>
        </div>

        {/* Measured state of the chain actually loaded in this build. */}
        <div className="grid grid-cols-3 gap-px max-w-2xl w-full mb-10 sm:mb-14 rounded overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
          {[
            { k: "Entries", v: String(CLEAN_CHAIN.length) },
            { k: "Co-signed", v: `${COSIGNED_COUNT} of ${CLEAN_CHAIN.length}` },
            { k: "Chain", v: CHAIN_ID.slice(0, 8) },
          ].map((s) => (
            <div key={s.k} className="px-2 sm:px-5 py-4" style={{ background: "#060c18" }}>
              <div className="font-mono text-sm sm:text-lg text-blue-300 break-all">{s.v}</div>
              <div className="text-[9px] sm:text-[10px] font-mono text-slate-600 uppercase tracking-widest mt-1">
                {s.k}
              </div>
            </div>
          ))}
        </div>

        <div
          className="grid grid-cols-1 md:grid-cols-3 gap-px max-w-4xl w-full text-left"
          style={{ background: "rgba(255,255,255,0.05)" }}
        >
          {FEATURES.map((f) => (
            <div key={f.title} className="p-6 sm:p-8" style={{ background: "#060c18" }}>
              <h3 className="text-white font-semibold mb-2 text-[13px] tracking-wide uppercase">
                {f.title}
              </h3>
              <p className="text-slate-500 text-xs leading-relaxed">{f.body}</p>
            </div>
          ))}
        </div>

        {/* Stated on the front page on purpose. A tool that hides its limits is asking to
            be caught by the first person who reads it carefully. */}
        <p className="text-[10px] sm:text-[11px] font-mono text-slate-600 max-w-2xl leading-relaxed mt-10 sm:mt-14">
          {COSIGNED_COUNT} of {CLEAN_CHAIN.length} entries in this chain carry a second signature.
          The certificate quotes the weakest tier it covers, not the strongest.
        </p>
      </main>

      <footer className="relative z-10 border-t border-white/5 px-5 sm:px-8 py-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
        <span className="text-[10px] sm:text-xs font-mono text-slate-600">
          Syntax Squad · GITAM (Deemed to be University), Hyderabad
        </span>
        <span className="text-[10px] sm:text-xs font-mono text-slate-700">
          Student prototype · not an accredited or empanelled product
        </span>
      </footer>
    </div>
  );
}
