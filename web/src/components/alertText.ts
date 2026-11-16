import type { AlertStatus } from "../api.ts";

// Plain-English wording for alert fields. Fixed strings only: nothing here repeats text from
// the alert, which is attacker-controlled.

export const STATUS_LABELS: Record<AlertStatus, string> = {
  new: "New",
  triaged: "Triaged",
  investigating: "Investigating",
  resolved: "Resolved",
  dismissed: "Dismissed",
};

/** Formats a status from the API, including one the console does not know yet. */
export function formatStatus(status: string): string {
  if (Object.hasOwn(STATUS_LABELS, status)) {
    return STATUS_LABELS[status as AlertStatus];
  }
  const words = status.replaceAll("_", " ").trim();
  return words === "" ? "Not set" : words.charAt(0).toUpperCase() + words.slice(1);
}

// Keys match lighthouse.triage.ReviewReason on the server. Unknown values get the generic
// sentence, so a reason added on the server later still reads sensibly.
const REVIEW_REASONS: Record<string, string> = {
  model_disabled: "Automatic triage is turned off for your organisation, so a person needs to assess this alert.",
  model_unavailable: "The AI service was not available when this alert arrived.",
  budget_exceeded: "Your organisation’s AI budget for the day was used up when this alert arrived.",
  refusal: "The AI declined to assess this alert. This happens with some security content.",
  max_tokens: "The AI’s assessment was cut off before it finished, so it was not used.",
  schema_invalid: "The AI’s assessment was not in the expected format, so it was not used.",
  unexpected_stop: "The AI stopped before finishing its assessment, so it was not used.",
  timeout: "The AI took too long to assess this alert.",
  rate_limited: "The AI service was too busy to assess this alert.",
  auth_error: "LightHouse could not sign in to the AI service.",
  connection_error: "LightHouse could not reach the AI service.",
  api_error: "The AI service returned an error.",
  internal_error: "Something went wrong in LightHouse while assessing this alert.",
};

const GENERIC_REVIEW_REASON = "LightHouse flagged this alert for a person to check.";

export function reviewReasonText(reason: string | null): string {
  if (reason !== null && Object.hasOwn(REVIEW_REASONS, reason)) {
    return REVIEW_REASONS[reason] ?? GENERIC_REVIEW_REASON;
  }
  return GENERIC_REVIEW_REASON;
}

/** Confidence in words. The number alone invites more precision than the model has. */
export function confidenceText(confidence: number | null): string {
  if (confidence === null) return "Not rated";
  if (confidence >= 0.8) return "High";
  if (confidence >= 0.5) return "Medium";
  return "Low";
}
