import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { Alert, AlertPage, ApiClient } from "../api.ts";
import { formatStatus } from "./alertText.ts";
import { describeError } from "./errorText.ts";
import { SeverityLabel, severityLabel } from "./SeverityLabel.tsx";

export const PAGE_SIZE = 50;

type MoreState = { readonly kind: "idle" } | { readonly kind: "loading" } | { readonly kind: "error"; readonly error: unknown };

type QueueState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: unknown }
  | {
      readonly kind: "ready";
      readonly items: readonly Alert[];
      readonly nextCursor: string | null;
      readonly more: MoreState;
    };

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

// Pages can overlap when new alerts arrive between requests. Keep the first copy of each id so
// list keys stay unique and nothing is shown twice.
function appendUnique(existing: readonly Alert[], incoming: readonly Alert[]): Alert[] {
  const seen = new Set(existing.map((alert) => alert.id));
  const merged = [...existing];
  for (const alert of incoming) {
    if (!seen.has(alert.id)) {
      seen.add(alert.id);
      merged.push(alert);
    }
  }
  return merged;
}

function readyState(page: AlertPage): QueueState {
  return {
    kind: "ready",
    items: appendUnique([], page.items),
    nextCursor: page.next_cursor,
    more: { kind: "idle" },
  };
}

function isAbort(signal: AbortSignal): boolean {
  return signal.aborted;
}

interface AlertsQueueProps {
  readonly api: ApiClient;
  /** Opens an alert's detail view. Without it, titles are plain text. */
  readonly onOpen?: ((id: string) => void) | undefined;
  /** The latest copy of an alert changed elsewhere (a status change), merged in by id. */
  readonly updated?: Alert | null | undefined;
  /** Shown under the heading, above the list (the general "Ask LightHouse" panel). */
  readonly beforeList?: ReactNode;
}

export function AlertsQueue({ api, onOpen, updated, beforeList }: AlertsQueueProps) {
  const [state, setState] = useState<QueueState>({ kind: "loading" });

  // Merge a changed alert in when the prop changes (React's "adjust state on prop change"
  // pattern: during render, not in an effect).
  const [mergedUpdate, setMergedUpdate] = useState(updated);
  if (updated !== mergedUpdate) {
    setMergedUpdate(updated);
    if (updated !== null && updated !== undefined && state.kind === "ready") {
      setState({ ...state, items: state.items.map((alert) => (alert.id === updated.id ? updated : alert)) });
    }
  }
  const [reloadCount, setReloadCount] = useState(0);
  const moreRequest = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    api.listAlerts({ limit: PAGE_SIZE }, controller.signal).then(
      (page) => {
        if (!isAbort(controller.signal)) setState(readyState(page));
      },
      (error: unknown) => {
        if (!isAbort(controller.signal)) setState({ kind: "error", error });
      },
    );
    return () => {
      controller.abort();
      moreRequest.current?.abort();
    };
  }, [api, reloadCount]);

  const reload = useCallback(() => {
    setState({ kind: "loading" });
    setReloadCount((count) => count + 1);
  }, []);

  const loadMore = useCallback(() => {
    if (state.kind !== "ready" || state.nextCursor === null || state.more.kind === "loading") {
      return;
    }
    const controller = new AbortController();
    moreRequest.current = controller;
    setState({ ...state, more: { kind: "loading" } });
    api.listAlerts({ limit: PAGE_SIZE, cursor: state.nextCursor }, controller.signal).then(
      (page) => {
        if (isAbort(controller.signal)) return;
        setState((current) =>
          current.kind === "ready"
            ? {
                kind: "ready",
                items: appendUnique(current.items, page.items),
                nextCursor: page.next_cursor,
                more: { kind: "idle" },
              }
            : current,
        );
      },
      (error: unknown) => {
        if (isAbort(controller.signal)) return;
        setState((current) => (current.kind === "ready" ? { ...current, more: { kind: "error", error } } : current));
      },
    );
  }, [api, state]);

  return (
    <section className="queue" aria-labelledby="queue-heading">
      <div className="page-head">
        <h1 id="queue-heading">Alerts</h1>
        <button type="button" className="button button-quiet" onClick={reload} disabled={state.kind === "loading"}>
          Refresh
        </button>
      </div>

      {beforeList}

      <p role="status" className="queue-status">
        {statusText(state)}
      </p>

      {state.kind === "error" && (
        <div role="alert" className="notice notice-error">
          <p>{describeError(state.error, "alerts")}</p>
          <button type="button" className="button" onClick={reload}>
            Try again
          </button>
        </div>
      )}

      {state.kind === "ready" && state.items.length > 0 && (
        <>
          <ul className="alert-list">
            {state.items.map((alert) => (
              <AlertRow key={alert.id} alert={alert} onOpen={onOpen} />
            ))}
          </ul>
          {state.nextCursor !== null && (
            <div className="queue-more">
              <button type="button" className="button" onClick={loadMore} disabled={state.more.kind === "loading"}>
                {state.more.kind === "loading" ? "Loading more alerts…" : "Load more alerts"}
              </button>
            </div>
          )}
          {state.more.kind === "error" && (
            <p role="alert" className="notice notice-error">
              {describeError(state.more.error, "more alerts")}
            </p>
          )}
        </>
      )}
    </section>
  );
}

function statusText(state: QueueState): string {
  switch (state.kind) {
    case "loading":
      return "Loading alerts…";
    case "error":
      return "";
    case "ready":
      if (state.items.length === 0) {
        return "No alerts to review. New alerts from your connected security services will appear here.";
      }
      return `Showing ${state.items.length} ${state.items.length === 1 ? "alert" : "alerts"}${
        state.nextCursor === null ? "." : ". More are available."
      }`;
  }
}

function formatTime(iso: string): string {
  return dateFormat.format(new Date(iso));
}

// Every string rendered here except created_at comes from a customer system and is
// attacker-controlled. It is only ever placed in React text nodes: never in
// dangerouslySetInnerHTML, an href, a src, a style or a class name.
function AlertRow({ alert, onOpen }: { alert: Alert; onOpen: ((id: string) => void) | undefined }) {
  const sourceDiffers = alert.source_severity !== alert.severity;
  const title = alert.title.trim() === "" ? "Untitled alert" : alert.title;
  return (
    <li className="alert">
      <div className="alert-severity">
        <SeverityLabel severity={alert.severity} />
        {sourceDiffers && (
          <p className="alert-source-severity">Source rated it {severityLabel(alert.source_severity)}</p>
        )}
      </div>
      <div className="alert-body">
        <h2 className="alert-title">
          {onOpen === undefined ? (
            title
          ) : (
            // The alert id is passed back as data; it is never built into a URL here.
            <button
              type="button"
              className="link-button"
              data-alert-id={alert.id}
              onClick={() => {
                onOpen(alert.id);
              }}
            >
              {title}
            </button>
          )}
        </h2>
        {alert.needs_human_review && <p className="review-flag">Needs human review</p>}
        {alert.summary !== null && alert.summary.trim() !== "" ? (
          <p className="alert-summary">{alert.summary}</p>
        ) : (
          <p className="alert-summary is-missing">No summary yet.</p>
        )}
        {alert.recommended_action !== null && alert.recommended_action.trim() !== "" && (
          <p className="alert-action">
            <strong>Next step:</strong> {alert.recommended_action}
          </p>
        )}
        <p className="alert-meta">
          From {alert.source.trim() === "" ? "an unnamed source" : alert.source}. Received{" "}
          <time dateTime={alert.created_at}>{formatTime(alert.created_at)}</time>. Status: {formatStatus(alert.status)}.
        </p>
      </div>
    </li>
  );
}
