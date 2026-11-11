import type { Severity } from "../api.ts";

const LABELS: Record<Severity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
  unknown: "Unknown",
};

// Filled steps on the five-step meter. "unknown" fills none and is drawn with dashed steps,
// so it never looks like "info". Colour is a third cue; the text label is the primary one.
const LEVELS: Record<Severity, number> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
  unknown: 0,
};

const STEPS = [1, 2, 3, 4, 5] as const;

export function severityLabel(severity: Severity): string {
  return LABELS[severity];
}

export function SeverityLabel({ severity }: { severity: Severity }) {
  const level = LEVELS[severity];
  return (
    <span className="severity" data-severity={severity}>
      <span className="severity-meter" aria-hidden="true">
        {STEPS.map((step) => (
          <span key={step} className={step <= level ? "severity-step is-filled" : "severity-step"} />
        ))}
      </span>
      <span className="severity-text">
        <span className="visually-hidden">Severity: </span>
        {LABELS[severity]}
      </span>
    </span>
  );
}
