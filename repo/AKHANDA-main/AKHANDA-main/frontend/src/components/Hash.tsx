import { useState } from "react";

/**
 * A 64-character SHA-256 is wider than a phone. Showing it in full forces the page to
 * scroll sideways, and a page that moves under the reader's thumb is the one thing this
 * screen must never do while a judge is holding it.
 *
 * So below `sm:` the digest is shortened to first8…last8 and the full value is one tap
 * away; from `sm:` up the whole digest is shown and wraps. The value is never altered,
 * only how much of it is on screen at once, `full` always carries the complete digest
 * to the clipboard.
 */
export default function Hash({
  value,
  className = "",
}: {
  value: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const short = value.length > 20 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard is blocked on insecure origins and in some kiosk browsers. Expanding
      // the digest still lets the reader check it by eye, so failing to copy is not
      // worth an error state.
      setOpen(true);
    }
  };

  return (
    <span className={`inline-flex items-baseline gap-1.5 min-w-0 ${className}`}>
      {/* Phone: tap to expand. Wrapped so the digest can never widen its container. */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title={value}
        aria-label={open ? "Collapse full hash" : `Show full hash, currently ${short}`}
        className="sm:hidden font-mono text-left break-all focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-400 rounded"
      >
        {open ? value : short}
      </button>

      {/* Tablet and up: the whole digest, wrapping inside its own box. */}
      <span className="hidden sm:inline font-mono break-all">{value}</span>

      <button
        type="button"
        onClick={() => void copy()}
        aria-label="Copy full hash"
        className="shrink-0 text-[9px] text-slate-600 hover:text-blue-400 focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-400 rounded px-0.5"
      >
        {copied ? "✓" : "copy"}
      </button>
    </span>
  );
}
