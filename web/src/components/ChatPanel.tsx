import { useEffect, useId, useRef, useState, type SubmitEvent } from "react";
import {
  ApiError,
  CHAT_MAX_QUESTION_LENGTH,
  type ApiClient,
  type ChatErrorCode,
  type ChatMessage,
  type ChatOutcome,
} from "../api.ts";

// "Ask LightHouse". The answer is model output about attacker-controlled alerts, so it is
// shown as plain text only (no markdown, no links, no HTML) and labelled as AI output. The
// conversation lives in this component's memory and is gone when it unmounts.

type TurnState =
  | { readonly kind: "streaming" }
  | { readonly kind: "done" }
  | { readonly kind: "stopped" }
  | { readonly kind: "error"; readonly message: string };

interface Turn {
  readonly id: number;
  readonly question: string;
  readonly answer: string;
  readonly state: TurnState;
}

// Fixed messages for every way an answer can fail. Nothing from the server's error body is
// ever shown.
export const CHAT_ERROR_MESSAGES: Record<ChatErrorCode, string> = {
  budget_exceeded:
    "Your organisation has used its AI allowance for today. Try again tomorrow, or ask an admin to raise the limit.",
  rate_limited: "Questions are coming in faster than LightHouse allows. Wait a minute, then ask again.",
  declined: "LightHouse declined to answer that question. Try asking it a different way.",
  unavailable: "The AI service is not available right now. Try again in a few minutes.",
  too_long: "The question or conversation is too long. Start a new conversation or shorten the question.",
  internal: "Something went wrong while answering. Ask again.",
  protocol: "The answer could not be read, so it was stopped. Ask again.",
  network: "The connection was lost while answering. Check your connection, then ask again.",
};

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.kind) {
      case "forbidden":
        return "Your role does not include Ask LightHouse. Ask an admin in your organisation to change it.";
      case "signed_out":
      case "unauthorized":
        return "Your session has ended. Sign in again to continue.";
      case "network":
        return CHAT_ERROR_MESSAGES.network;
      default:
        return CHAT_ERROR_MESSAGES.internal;
    }
  }
  return CHAT_ERROR_MESSAGES.internal;
}

/** Completed exchanges only: a stopped or failed answer is not context for the next one. */
function historyFrom(turns: readonly Turn[]): ChatMessage[] {
  return turns
    .filter((turn) => turn.state.kind === "done")
    .flatMap((turn): ChatMessage[] => [
      { role: "user", content: turn.question },
      { role: "assistant", content: turn.answer },
    ]);
}

interface ChatPanelProps {
  readonly api: ApiClient;
  /** Scopes questions to one alert, or null for general questions. */
  readonly alertId: string | null;
  /** One sentence saying what the panel can answer about. */
  readonly intro: string;
  /** False when the surrounding disclosure already names the panel. */
  readonly showHeading?: boolean;
}

export function ChatPanel({ api, alertId, intro, showHeading = true }: ChatPanelProps) {
  const [turns, setTurns] = useState<readonly Turn[]>([]);
  const [question, setQuestion] = useState("");
  const [inputError, setInputError] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);
  const nextId = useRef(1);
  const headingId = useId();
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();

  // Stop any answer in flight when the panel goes away (or moves to another alert).
  useEffect(
    () => () => {
      controller.current?.abort();
      controller.current = null;
    },
    [api, alertId],
  );

  const streaming = turns.some((turn) => turn.state.kind === "streaming");

  function updateTurn(id: number, update: (turn: Turn) => Turn) {
    setTurns((current) => current.map((turn) => (turn.id === id ? update(turn) : turn)));
  }

  function stopCurrent() {
    controller.current?.abort();
    controller.current = null;
    setTurns((current) =>
      current.map((turn) => (turn.state.kind === "streaming" ? { ...turn, state: { kind: "stopped" } } : turn)),
    );
  }

  function ask(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const text = question.trim();
    if (text === "") {
      setInputError("Type a question first.");
      return;
    }
    if (text.length > CHAT_MAX_QUESTION_LENGTH) {
      setInputError(`Questions can be up to ${CHAT_MAX_QUESTION_LENGTH.toLocaleString()} characters.`);
      return;
    }

    // A new question replaces any answer still arriving.
    const history = historyFrom(turns);
    stopCurrent();
    const request = new AbortController();
    controller.current = request;
    const id = nextId.current;
    nextId.current += 1;
    setTurns((current) => [...current, { id, question: text, answer: "", state: { kind: "streaming" } }]);
    setQuestion("");
    setInputError(null);

    const onDelta = (delta: string) => {
      if (request.signal.aborted) return;
      updateTurn(id, (turn) => ({ ...turn, answer: turn.answer + delta }));
    };

    let started: Promise<ChatOutcome>;
    try {
      started = api.streamChat({ question: text, alertId, history }, onDelta, request.signal);
    } catch (error) {
      started = Promise.reject(error instanceof Error ? error : new Error("Request not sent."));
    }
    started.then(
      (outcome) => {
        if (request.signal.aborted) return;
        controller.current = null;
        updateTurn(id, (turn) => ({
          ...turn,
          state: outcome.kind === "done" ? { kind: "done" } : { kind: "error", message: CHAT_ERROR_MESSAGES[outcome.code] },
        }));
      },
      (error: unknown) => {
        if (request.signal.aborted) return;
        controller.current = null;
        updateTurn(id, (turn) => ({ ...turn, state: { kind: "error", message: errorMessage(error) } }));
      },
    );
  }

  function newConversation() {
    stopCurrent();
    setTurns([]);
  }

  const latest = turns.at(-1);

  return (
    <section className="chat" aria-labelledby={showHeading ? headingId : undefined} aria-label={showHeading ? undefined : "Ask LightHouse"}>
      {showHeading && (
        <h2 id={headingId} className="detail-subhead">
          Ask LightHouse
        </h2>
      )}
      <p className="field-hint">
        {intro} Answers are written by AI and can be wrong. Check them against the alert before you act.
      </p>

      {turns.length > 0 && (
        <ol className="chat-log">
          {turns.map((turn) => (
            <li key={turn.id} className="chat-turn">
              <p className="chat-who">You asked</p>
              <p className="chat-text">{turn.question}</p>
              <p className="chat-who">
                LightHouse AI answered <span className="ai-label">(AI output, may be wrong)</span>
              </p>
              {turn.answer !== "" ? (
                <p className="chat-text chat-answer">{turn.answer}</p>
              ) : (
                turn.state.kind === "streaming" && <p className="chat-text is-missing">Thinking…</p>
              )}
              {turn.state.kind === "stopped" && <p className="chat-note">Stopped. This answer is incomplete.</p>}
              {turn.state.kind === "error" && (
                <p className="chat-note chat-note-error">
                  {turn.answer !== "" && "This answer is incomplete. "}
                  {turn.state.message}
                </p>
              )}
            </li>
          ))}
        </ol>
      )}

      <p role="status" className="visually-hidden">
        {latest === undefined
          ? ""
          : latest.state.kind === "streaming"
            ? "LightHouse is answering."
            : latest.state.kind === "done"
              ? "LightHouse has answered."
              : latest.state.kind === "error"
                ? latest.state.message
                : "The answer was stopped."}
      </p>

      <form className="chat-form" onSubmit={ask} noValidate>
        <label htmlFor={inputId}>Your question</label>
        <p id={hintId} className="field-hint">
          Up to {CHAT_MAX_QUESTION_LENGTH.toLocaleString()} characters. Do not paste passwords or keys.
        </p>
        <textarea
          id={inputId}
          rows={3}
          maxLength={CHAT_MAX_QUESTION_LENGTH}
          value={question}
          onChange={(event) => {
            setQuestion(event.target.value);
            setInputError(null);
          }}
          aria-describedby={inputError === null ? hintId : `${hintId} ${errorId}`}
          aria-invalid={inputError !== null}
        />
        {inputError !== null && (
          <p id={errorId} role="alert" className="field-error">
            {inputError}
          </p>
        )}
        <div className="chat-actions">
          <button type="submit" className="button button-primary">
            Ask
          </button>
          {streaming && (
            <button type="button" className="button button-quiet" onClick={stopCurrent}>
              Stop answering
            </button>
          )}
          {turns.length > 0 && !streaming && (
            <button type="button" className="button button-quiet" onClick={newConversation}>
              New conversation
            </button>
          )}
        </div>
      </form>
    </section>
  );
}
