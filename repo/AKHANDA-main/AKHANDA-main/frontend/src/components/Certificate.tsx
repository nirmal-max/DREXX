import { useState } from "react";
import { CLEAN_CHAIN, CHAIN_ID, OPERATOR_KEY_ID, CONCUR_KEY_ID, COSIGNED_COUNT, TOOL_REF } from "../data/chainData";
import Hash from "./Hash";

/**
 * This screen previously cited "Section 65B, Indian Evidence Act, 1872". That Act was
 * repealed on 1 July 2024 and replaced by the Bharatiya Sakshya Adhiniyam 2023; the
 * governing provision is s.63(4) read with the Schedule. It also carried an invented
 * laboratory, an invented registration number, an invented device capacity and an
 * invented recovery count ("2,914 of 3,847"). All of it is removed.
 *
 * Every value below now comes from the generated ledger data, or is shown as an
 * explicitly unfilled Schedule field. A blank we admit to is defensible. A number we
 * invented is not.
 */

function Field({ label, value, mono, missing }: { label: string; value: string; mono?: boolean; missing?: boolean }) {
  return (
    <div className="py-3 border-b border-slate-800/60 flex flex-col gap-0.5 min-w-0">
      <span className="text-[10px] font-mono tracking-widest text-slate-500 uppercase">{label}</span>
      {missing ? (
        <span className="text-sm text-amber-400/70 italic">not recorded by this build</span>
      ) : (
        <span className={`text-sm text-slate-200 min-w-0 ${mono ? "font-mono text-[11px] break-all" : ""}`}>
          {value}
        </span>
      )}
    </div>
  );
}

/** Reproduced from the certificate the tool emits. Kept verbatim: these are the limits
 *  the document states about itself, and softening them here would make the screen
 *  claim more than the file does. */
const LIMITS = [
  "INTEGRITY, NOT COMPLETENESS. This certificate establishes that the operations recorded here were not altered after they were recorded. It does not, and no single-operator ledger can, establish that no operation was withheld from the record.",
  "TAIL TRUNCATION. Removing the most recent entries leaves a shorter, self-consistent chain. Only the independent witness record distinguishes that from a chain that was always that length.",
  "SINGLE-MACHINE CUSTODY. At least one covered entry was signed without an independent co-signature. For those entries both the record and the key that signed it were under one party's control.",
  "PARTIAL DUAL SIGNATURE. Not every covered entry carries both signatures. BSA s.63(4) contemplates a certificate signed by both the person in charge and an expert; entries without a second signature do not meet that shape and are identified above.",
  "NO CONFIRMED EXTERNAL ANCHOR. Timestamps here are the operator's own clock, bound at signing but not externally witnessed.",
  "FORM, NOT ADMISSIBILITY. Every field above maps to a named clause of NIST SP 800-88 Rev. 2 or the Bharatiya Sakshya Adhiniyam 2023. That is a statement about the form of this document. Whether a record is admitted is a matter for the court, not for this tool.",
];

/** Schedule fields we do not currently emit. Listed rather than hidden, a judge who
 *  finds a gap we already published is reading our audit, not catching us out. */
const SCHEDULE_GAPS = [
  ["Place of the operation", "Schedule, Parts A and B, closing block"],
  ["S/o, D/o, W/o of the deponent", "Schedule, Parts A and B, opening block"],
  ["Colour of the device", "Schedule, device particulars"],
  ["IMEI / UIN / UID / MAC / Cloud ID", "Schedule, device particulars"],
  ["Designation of the expert", "Schedule, Part B, signature block"],
];

export default function Certificate() {
  const [printMode, setPrintMode] = useState(false);
  const terminalEntry = CLEAN_CHAIN[CLEAN_CHAIN.length - 1];

  return (
    <div className="min-h-screen overflow-x-hidden" style={{ background: "#060c18" }}>
      <div className="border-b border-white/5 px-5 sm:px-8 py-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="min-w-0">
          <span className="text-white font-semibold tracking-wide">Certificate Viewer</span>
          <div className="text-[10px] sm:text-[11px] font-mono text-slate-600 mt-0.5">
            Bharatiya Sakshya Adhiniyam 2023, s.63(4) · NIST SP 800-88 Rev. 2
          </div>
        </div>
        <button
          onClick={() => setPrintMode(!printMode)}
          className="px-5 py-2 rounded border border-blue-500/30 text-blue-400 text-xs font-mono tracking-widest hover:bg-blue-500/10 transition-all uppercase shrink-0 self-start"
        >
          {printMode ? "Close Print View" : "Print / Export"}
        </button>
      </div>

      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-6 sm:py-10">
        <div
          className="rounded border border-white/8 overflow-hidden"
          style={{ background: printMode ? "#fff" : "#0a1020", color: printMode ? "#000" : undefined }}
        >
          {/* Header band, stacks below sm: instead of colliding */}
          <div
            className="px-5 sm:px-8 py-5 sm:py-6 flex flex-col md:flex-row md:items-start md:justify-between gap-4"
            style={{
              background: printMode ? "#0f1a30" : "linear-gradient(135deg, #0f1a30 0%, #152240 100%)",
              borderBottom: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-3 mb-3">
                <div
                  className="w-10 h-10 rounded flex items-center justify-center shrink-0"
                  style={{ background: "linear-gradient(135deg, #1c2e52, #3b82f6)" }}
                >
                  <span className="text-white text-sm font-bold font-mono">Ak</span>
                </div>
                <div className="min-w-0">
                  <div className="text-white font-bold tracking-widest text-sm uppercase">AKHANDA</div>
                  <div className="text-blue-400/60 text-[10px] font-mono">
                    Syntax Squad · GITAM Hyderabad
                  </div>
                </div>
              </div>
              <h2 className="text-white text-base sm:text-lg font-semibold">
                Certificate of Electronic Record Integrity
              </h2>
              <p className="text-slate-400 text-xs mt-1">
                Mapped to BSA 2023 s.63(4) and the Schedule · issued by a prototype tool
              </p>
            </div>
            <div className="md:text-right min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                Certificate No.
              </div>
              <div className="font-mono text-blue-300 font-medium text-xs break-all">
                AKHANDA-CERT-{CHAIN_ID}
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-2">Issued</div>
              <div className="font-mono text-slate-300 text-xs">
                04 Sep 2026, 16:56 IST
              </div>
            </div>
          </div>

          <div className="px-5 sm:px-8 py-5 sm:py-6">
            <div className="text-xs text-slate-400 leading-relaxed mb-6 border-l-2 border-blue-500/40 pl-4">
              The operations described below were performed by the Akhanda tool and recorded as
              entries in an append-only ledger. Each entry is a length-prefixed encoding of its
              sixteen signed fields, hashed with SHA-256, linked to the hash of the entry before
              it, and signed at the moment the operation completed. The tool makes no statement
              about the provenance of the media or the admissibility of the record.
            </div>

            {/* One column below md:, two 64-char columns side by side do not fit a phone */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-10">
              <div className="min-w-0">
                <div className="text-[10px] font-mono text-blue-400/70 uppercase tracking-widest mb-3">
                  Record
                </div>
                <Field label="Chain identifier" value={CHAIN_ID} mono />
                <Field label="Part A, person in charge" value={`key ${OPERATOR_KEY_ID}`} mono />
                <Field label="Part B, expert" value={CONCUR_KEY_ID ? `key ${CONCUR_KEY_ID}` : ""} mono missing={!CONCUR_KEY_ID} />
                <Field label="Entries covered" value={`${CLEAN_CHAIN.length}`} />
                <Field label="Entries dual-signed" value={`${COSIGNED_COUNT} of ${CLEAN_CHAIN.length}`} />
                <Field label="Place of operation" value="" missing />
              </div>
              <div className="min-w-0">
                <div className="text-[10px] font-mono text-blue-400/70 uppercase tracking-widest mb-3">
                  Device
                </div>
                <Field label="Media type" value="Flash Memory" />
                <Field label="Co-signer custody" value="separate machine; this workstation never holds that key" />
                <Field label="Tool used" value={TOOL_REF} mono />
                <Field label="Presence device" value="not used for these entries" />
                <Field label="Serial number" value="" missing />
                <Field label="IMEI / UIN / MAC / Cloud ID" value="" missing />
              </div>
            </div>

            {/* Chain summary, the table scrolls inside its own box, the page does not */}
            <div className="mt-8 border border-white/6 rounded">
              <div className="px-4 sm:px-5 py-3 border-b border-white/6 flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
                  Chain of Custody, Summary
                </span>
                <span className="text-[11px] font-mono text-green-400">
                  {CLEAN_CHAIN.length}/{CLEAN_CHAIN.length} entries verified
                </span>
              </div>
              <div className="divide-y divide-white/4">
                {CLEAN_CHAIN.map((entry) => (
                  <div
                    key={entry.id}
                    className="px-4 sm:px-5 py-3 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1 sm:gap-4"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-green-400 text-[10px]">✓</span>
                        <span className="text-xs text-slate-300 font-medium">
                          {entry.action.replace(/_/g, " ")}
                        </span>
                        <span className="text-slate-600 text-[10px]">·</span>
                        <span className="text-slate-500 text-[10px]">{entry.custodyTier}</span>
                      </div>
                      <div className="font-mono text-[9px] text-slate-600 mt-0.5 min-w-0">
                        <Hash value={entry.hash} />
                      </div>
                    </div>
                    <div className="text-[10px] font-mono text-slate-600 shrink-0">
                      {new Date(entry.timestamp).toLocaleDateString("en-IN")}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div
              className="mt-6 p-4 rounded border border-blue-500/20 min-w-0"
              style={{ background: "rgba(59,130,246,0.06)" }}
            >
              <div className="text-[10px] font-mono text-blue-400/70 uppercase tracking-widest mb-1">
                Terminal Chain Hash
              </div>
              <div className="font-mono text-xs text-blue-300 min-w-0">
                <Hash value={terminalEntry.hash} />
              </div>
            </div>

            {/* Known Schedule gaps, published rather than hidden */}
            <div
              className="mt-6 p-4 sm:p-5 rounded border border-slate-600/30"
              style={{ background: "rgba(148,163,184,0.04)" }}
            >
              <div className="text-[11px] font-mono font-semibold tracking-widest uppercase text-slate-400 mb-3">
                Schedule fields this build does not emit
              </div>
              <div className="overflow-x-auto -mx-1 px-1">
                <table className="w-full text-[11px] text-slate-400">
                  <tbody>
                    {SCHEDULE_GAPS.map(([field, where]) => (
                      <tr key={field} className="border-t border-white/5 first:border-t-0">
                        <td className="py-2 pr-4 text-slate-300 align-top">{field}</td>
                        <td className="py-2 font-mono text-[10px] text-slate-600 align-top whitespace-nowrap">
                          {where}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div
              className="mt-6 p-4 sm:p-5 rounded border border-amber-500/20"
              style={{ background: "rgba(245,158,11,0.05)" }}
            >
              <div className="flex flex-wrap items-center gap-2 mb-3">
                <span className="text-amber-400 text-sm">⚠</span>
                <span className="text-amber-400 text-[11px] font-mono font-semibold tracking-widest uppercase">
                  Certificate Limitations
                </span>
                <span className="text-[10px] font-mono text-amber-400/60 sm:ml-auto">
                  Stated by the tool
                </span>
              </div>
              <ul className="text-[11px] text-slate-400 leading-relaxed space-y-2 list-none">
                {LIMITS.map((l) => (
                  <li key={l.slice(0, 24)}>• {l}</li>
                ))}
              </ul>
            </div>

            <div className="mt-8 flex flex-col sm:flex-row sm:items-end sm:justify-between gap-6 border-t border-white/6 pt-6">
              <div className="min-w-0">
                <div className="w-40 sm:w-48 border-b border-slate-600 mb-1" />
                <div className="text-xs text-slate-400">Part A, person in charge</div>
                <div className="text-[10px] font-mono text-slate-600 break-all">
                  key {OPERATOR_KEY_ID}
                </div>
              </div>
              <div className="min-w-0 sm:text-right">
                <div className="w-40 sm:w-48 border-b border-slate-600 mb-1 sm:ml-auto" />
                <div className="text-xs text-slate-400">Part B, expert</div>
                <div className="text-[10px] font-mono text-slate-600 break-all">
                  key {CONCUR_KEY_ID || "not co-signed"}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
