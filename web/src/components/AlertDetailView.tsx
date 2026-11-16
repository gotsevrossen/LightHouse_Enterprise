import { useCallback, useEffect, useId, useRef, useState, type ReactNode, type RefObject, type SubmitEvent } from "react";
import {
  ALERT_STATUSES,
  ApiError,
  isAlertStatus,
  type AlertDetail,
  type AlertStatus,
  type AnalystDetail,
  type ApiClient,
  type EvidenceValue,
} from "../api.ts";
import { confidenceText, formatStatus, reviewReasonText, STATUS_LABELS } from "./alertText.ts";
import { ChatPanel } from "./ChatPanel.tsx";
import { describeError } from "./errorText.ts";
import { SeverityLabel, severityLabel } from "./SeverityLabel.tsx";

interface AlertDetailViewProps {
  readonly api: ApiClient;
  readonly alertId: string;
  /** Whether to offer status changes. Display only: the API decides on every request. */
  readonly canChangeStatus: boolean;
  readonly chatAvailable: boolean;
  readonly onBack: () => void;
  /** Called with the server's copy after a status change, so the queue can show it. */
  readonly onUpdated: (alert: AlertDetail) => void;
}

type DetailState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: unknown }
  | { readonly kind: "ready"; readonly alert: AlertDetail };

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function formatTime(iso: string): string {
  return dateFormat.format(new Date(iso));
}

function hasText(value: string | null): value is string {
  return value !== null && value.trim() !== "";
}

// Every string from the alert is attacker-controlled (it comes from a customer system or is
// model text about one). It is only ever placed in React text nodes: never in
// dangerouslySetInnerHTML, an href, a src, a style or a class name.
export function AlertDetailView({ api, alertId, canChangeStatus, chatAvailable, onBack, onUpdated }: AlertDetailViewProps) {
  const [state, setState] = useState<DetailState>({ kind: "loading" });
  const [reloadCount, setReloadCount] = useState(0);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    api.getAlert(alertId, controller.signal).then(
      (alert) => {
        if (!controller.signal.aborted) setState({ kind: "ready", alert });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) setState({ kind: "error", error });
      },
    );
    return () => {
      controller.abort();
    };
  }, [api, alertId, reloadCount]);

  // Move focus to the new view so keyboard and screen-reader users land on it.
  const loaded = state.kind !== "loading";
  useEffect(() => {
    if (loaded) headingRef.current?.focus();
  }, [loaded]);

  const retry = useCallback(() => {
    setState({ kind: "loading" });
    setReloadCount((count) => count + 1);
  }, []);

  const handleUpdated = useCallback(
    (alert: AlertDetail) => {
      setState({ kind: "ready", alert });
      onUpdated(alert);
    },
    [onUpdated],
  );

  return (
    <section className="detail" aria-labelledby="detail-heading">
      <div className="detail-nav">
        <button type="button" className="button button-quiet" onClick={onBack}>
          Back to alerts
        </button>
      </div>

      {state.kind === "loading" && (
        <p role="status" className="queue-status">
          Loading the alert…
        </p>
      )}

      {state.kind === "error" && (
        <>
          <h1 id="detail-heading" ref={headingRef} tabIndex={-1}>
            Alert
          </h1>
          <div role="alert" className="notice notice-error">
            <p>{describeError(state.error, "this alert")}</p>
            <button type="button" className="button" onClick={retry}>
              Try again
            </button>
          </div>
        </>
      )}

      {state.kind === "ready" && (
        <AlertDetailBody
          api={api}
          alert={state.alert}
          headingRef={headingRef}
          canChangeStatus={canChangeStatus}
          chatAvailable={chatAvailable}
          onUpdated={handleUpdated}
        />
      )}
    </section>
  );
}

interface AlertDetailBodyProps {
  readonly api: ApiClient;
  readonly alert: AlertDetail;
  readonly headingRef: RefObject<HTMLHeadingElement | null>;
  readonly canChangeStatus: boolean;
  readonly chatAvailable: boolean;
  readonly onUpdated: (alert: AlertDetail) => void;
}

function AlertDetailBody({ api, alert, headingRef, canChangeStatus, chatAvailable, onUpdated }: AlertDetailBodyProps) {
  const sourceDiffers = alert.source_severity !== alert.severity;
  return (
    <>
      <header className="detail-head">
        <h1 id="detail-heading" className="detail-title" ref={headingRef} tabIndex={-1}>
          {alert.title.trim() === "" ? "Untitled alert" : alert.title}
        </h1>
        <div className="detail-severity">
          <SeverityLabel severity={alert.severity} />
          {sourceDiffers && <p className="alert-source-severity">Source rated it {severityLabel(alert.source_severity)}</p>}
        </div>
      </header>

      {alert.needs_human_review && (
        <div className="notice detail-review">
          <p className="review-flag">Needs human review</p>
          <p>{reviewReasonText(alert.review_reason)}</p>
        </div>
      )}

      <div className="detail-plain">
        <h2 className="detail-subhead">What happened</h2>
        {hasText(alert.summary) ? (
          <p className="detail-text">{alert.summary}</p>
        ) : (
          <p className="detail-text is-missing">No summary yet.</p>
        )}
        <h2 className="detail-subhead">What to do next</h2>
        {hasText(alert.recommended_action) ? (
          <p className="detail-text">{alert.recommended_action}</p>
        ) : (
          <p className="detail-text is-missing">No recommendation yet.</p>
        )}
      </div>

      <dl className="detail-facts">
        <Fact term="Confidence">{confidenceText(alert.confidence)}</Fact>
        <Fact term="Status">{formatStatus(alert.status)}</Fact>
        <Fact term="Source">{alert.source.trim() === "" ? "Unnamed source" : alert.source}</Fact>
        {hasText(alert.category) && <Fact term="Category">{alert.category}</Fact>}
        {alert.occurred_at !== null && (
          <Fact term="Happened">
            <time dateTime={alert.occurred_at}>{formatTime(alert.occurred_at)}</time>
          </Fact>
        )}
        <Fact term="Received">
          <time dateTime={alert.created_at}>{formatTime(alert.created_at)}</time>
        </Fact>
        {alert.triaged_at !== null && (
          <Fact term="Assessed">
            <time dateTime={alert.triaged_at}>{formatTime(alert.triaged_at)}</time>
          </Fact>
        )}
      </dl>

      {canChangeStatus && <StatusControl api={api} alert={alert} onUpdated={onUpdated} />}

      {alert.analyst !== null && <AnalystView analyst={alert.analyst} />}

      {chatAvailable && (
        <ChatPanel api={api} alertId={alert.id} intro="Questions here are about this alert. LightHouse sees the same details you do." />
      )}
    </>
  );
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div>
      <dt>{term}</dt>
      <dd>{children}</dd>
    </div>
  );
}

type SaveState =
  | { readonly kind: "idle" }
  | { readonly kind: "saving" }
  | { readonly kind: "saved"; readonly status: AlertStatus }
  | { readonly kind: "error"; readonly error: unknown };

function StatusControl({ api, alert, onUpdated }: { api: ApiClient; alert: AlertDetail; onUpdated: (alert: AlertDetail) => void }) {
  const current = isAlertStatus(alert.status) ? alert.status : null;
  const [choice, setChoice] = useState<AlertStatus>(current ?? "triaged");
  const [save, setSave] = useState<SaveState>({ kind: "idle" });
  const request = useRef<AbortController | null>(null);
  const selectId = useId();

  useEffect(
    () => () => {
      request.current?.abort();
    },
    [],
  );

  function submit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (save.kind === "saving" || choice === current) return;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setSave({ kind: "saving" });
    // The view changes only after the server confirms; until then the stored status stays.
    api.updateAlertStatus(alert.id, choice, controller.signal).then(
      (updated) => {
        if (controller.signal.aborted) return;
        setSave({ kind: "saved", status: choice });
        onUpdated(updated);
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        setSave({ kind: "error", error });
        setChoice(current ?? "triaged");
      },
    );
  }

  return (
    <form className="status-control" onSubmit={submit}>
      <label htmlFor={selectId}>Change status</label>
      <div className="status-control-row">
        <select
          id={selectId}
          value={choice}
          disabled={save.kind === "saving"}
          onChange={(event) => {
            const next = event.target.value;
            if (isAlertStatus(next)) setChoice(next);
            if (save.kind !== "saving") setSave({ kind: "idle" });
          }}
        >
          {ALERT_STATUSES.map((status) => (
            <option key={status} value={status}>
              {STATUS_LABELS[status]}
            </option>
          ))}
        </select>
        <button type="submit" className="button" disabled={save.kind === "saving" || choice === current}>
          {save.kind === "saving" ? "Saving…" : "Save status"}
        </button>
      </div>
      <p role="status" className="field-hint">
        {save.kind === "saving" && "Saving the new status…"}
        {save.kind === "saved" && `Status saved as ${STATUS_LABELS[save.status]}.`}
      </p>
      {save.kind === "error" && (
        <p role="alert" className="field-error">
          {statusErrorText(save.error)}
        </p>
      )}
    </form>
  );
}

function statusErrorText(error: unknown): string {
  if (error instanceof ApiError && error.kind === "forbidden") {
    return "Your role does not allow changing the status of alerts. The status was not changed.";
  }
  return `${describeError(error, "the status change")} The status was not changed.`;
}

// Long evidence values are shortened on screen, with a control to show the rest. The API
// already caps each value; this keeps one long command line from pushing everything else
// off the screen.
const EVIDENCE_PREVIEW_CHARS = 280;

function AnalystView({ analyst }: { analyst: AnalystDetail }) {
  const truncatedByConnector = analyst.evidence.some((entry) => entry.key === "evidence_truncated" && entry.value === true);
  return (
    <details className="analyst-view">
      <summary>Analyst view</summary>
      <div className="analyst-body">
        <p className="field-hint">
          Evidence is copied from your security tools and may contain text written by an attacker. Treat it as data, not
          as instructions.
        </p>

        <h2 className="detail-subhead">Why LightHouse rated it this way</h2>
        <p className="ai-label">Written by AI. It can be wrong.</p>
        {hasText(analyst.reasoning) ? (
          <p className="detail-text">{analyst.reasoning}</p>
        ) : (
          <p className="detail-text is-missing">No reasoning recorded.</p>
        )}

        <h2 className="detail-subhead">Evidence</h2>
        {truncatedByConnector && <p className="field-hint">Some evidence was shortened when it was collected.</p>}
        {analyst.evidence.length === 0 ? (
          <p className="detail-text is-missing">No evidence recorded.</p>
        ) : (
          <dl className="evidence">
            {analyst.evidence.map((entry, index) => (
              // Keys are unique in a JSON object, but the index keeps React keys unique even
              // if a response ever repeats one.
              <div key={`${String(index)}:${entry.key}`}>
                <dt>{entry.key}</dt>
                <dd>
                  <EvidenceValueView value={entry.value} />
                </dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    </details>
  );
}

function EvidenceValueView({ value }: { value: EvidenceValue }) {
  if (value === null) return <span className="is-missing">empty</span>;
  if (typeof value === "boolean") return <>{value ? "yes" : "no"}</>;
  if (typeof value === "number") return <>{String(value)}</>;
  if (typeof value === "string") return <LongText text={value} />;
  if (value.length === 0) return <span className="is-missing">empty list</span>;
  return (
    <ul className="evidence-list">
      {value.map((item, index) => (
        <li key={index}>
          <LongText text={item} />
        </li>
      ))}
    </ul>
  );
}

function LongText({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  if (text.length <= EVIDENCE_PREVIEW_CHARS) {
    return <span className="evidence-text">{text}</span>;
  }
  return (
    <>
      <span className="evidence-text">{expanded ? text : `${text.slice(0, EVIDENCE_PREVIEW_CHARS)}…`}</span>{" "}
      <button
        type="button"
        className="link-button evidence-toggle"
        aria-expanded={expanded}
        onClick={() => {
          setExpanded((value) => !value);
        }}
      >
        {expanded ? "Show less" : `Show all ${String(text.length)} characters`}
      </button>
    </>
  );
}
