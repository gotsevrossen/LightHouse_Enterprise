import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../api.ts";
import { bodyText, jsonResponse, ndjson, ndjsonResponse, routedFetch, signedInAuth } from "../test/fixtures.ts";
import { CHAT_ERROR_MESSAGES, ChatPanel } from "./ChatPanel.tsx";

const START = { type: "start" };
const DONE = { type: "done" };

/** A response whose body the test feeds by hand. */
function controlledStream() {
  const encoder = new TextEncoder();
  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  const cancelled = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
    },
    cancel: cancelled,
  });
  return {
    response: ndjsonResponse(body),
    send(events: readonly unknown[]) {
      try {
        controller?.enqueue(encoder.encode(ndjson(events)));
      } catch {
        // The reader cancelled the stream; nothing more can arrive.
      }
    },
    close() {
      controller?.close();
    },
    cancelled,
  };
}

function setup(stream: (url: URL, init: RequestInit | undefined) => Response | Promise<Response>, alertId: string | null = null) {
  const fetch = routedFetch({ "/api/chat/stream": stream });
  const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
  const view = render(<ChatPanel api={api} alertId={alertId} intro="Ask about your alerts." />);
  return { ...view, fetch };
}

function ask(text: string) {
  fireEvent.change(screen.getByLabelText("Your question"), { target: { value: text } });
  fireEvent.click(screen.getByRole("button", { name: "Ask" }));
}

function bodyOf(init: RequestInit | undefined): { question: string; alert_id: string | null; history: unknown[] } {
  return JSON.parse(bodyText(init)) as { question: string; alert_id: string | null; history: unknown[] };
}

describe("ChatPanel", () => {
  it("labels answers as AI output that may be wrong", () => {
    setup(() => jsonResponse({}, 503));
    expect(screen.getByText(/Answers are written by AI and can be wrong/)).toBeTruthy();
  });

  it("streams an answer in as plain text, then marks it complete", async () => {
    const stream = controlledStream();
    const { fetch } = setup(() => stream.response, "alert-7");

    ask("  Is this sign-in dangerous?  ");
    expect(await screen.findByText("Thinking…")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("LightHouse is answering.");
    expect(screen.getByRole("button", { name: "Stop answering" })).toBeTruthy();

    stream.send([START, { type: "delta", text: "**Probably** not.\n" }]);
    expect(await screen.findByText(/\*\*Probably\*\* not\./)).toBeTruthy();
    stream.send([{ type: "delta", text: "Check with the user." }, DONE]);

    await waitFor(() => {
      expect(screen.getByRole("status").textContent).toBe("LightHouse has answered.");
    });
    const answer = document.querySelector(".chat-answer");
    expect(answer?.textContent).toBe("**Probably** not.\nCheck with the user.");
    expect(answer?.querySelector("strong, b, a")).toBeNull();
    expect(screen.getByText("(AI output, may be wrong)")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Stop answering" })).toBeNull();
    expect(bodyOf(fetch.mock.calls[0]?.[1])).toEqual({ question: "Is this sign-in dangerous?", alert_id: "alert-7", history: [] });
  });

  it("renders hostile answer text literally", async () => {
    const html = '<img src=x onerror="window.__pwned=1"><a href="javascript:alert(1)">x</a>';
    const { container } = setup(() => ndjsonResponse(ndjson([START, { type: "delta", text: html }, DONE])));
    ask("q");
    expect(await screen.findByText(html)).toBeTruthy();
    expect(container.querySelector("img, a, [onerror]")).toBeNull();
    expect((window as unknown as { __pwned?: unknown }).__pwned).toBeUndefined();
  });

  it("sends completed exchanges as history on the next question", async () => {
    let call = 0;
    const { fetch } = setup(() => {
      call += 1;
      return ndjsonResponse(ndjson([START, { type: "delta", text: `answer ${String(call)}` }, DONE]));
    });
    ask("first question");
    expect(await screen.findByText("answer 1")).toBeTruthy();
    ask("second question");
    expect(await screen.findByText("answer 2")).toBeTruthy();

    expect(bodyOf(fetch.mock.calls[1]?.[1]).history).toEqual([
      { role: "user", content: "first question" },
      { role: "assistant", content: "answer 1" },
    ]);
  });

  it.each([
    ["budget_exceeded"],
    ["rate_limited"],
    ["declined"],
    ["unavailable"],
    ["too_long"],
    ["internal"],
  ] as const)("shows a fixed message for the %s error", async (code) => {
    setup(() => ndjsonResponse(ndjson([START, { type: "error", code, message: "<b>server text</b>" }])));
    ask("q");
    expect(await screen.findByText(CHAT_ERROR_MESSAGES[code], { selector: ".chat-note" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe(CHAT_ERROR_MESSAGES[code]);
    expect(document.body.textContent).not.toContain("server text");
  });

  it("marks a broken stream as incomplete and leaves it out of the history", async () => {
    let call = 0;
    const { fetch } = setup(() => {
      call += 1;
      return call === 1
        ? ndjsonResponse(`${JSON.stringify(START)}\n${JSON.stringify({ type: "delta", text: "half" })}\n{oops\n`)
        : ndjsonResponse(ndjson([START, DONE]));
    });
    ask("first");
    const note = await screen.findByText(/This answer is incomplete\./);
    expect(note.textContent).toContain(CHAT_ERROR_MESSAGES.protocol);
    ask("second");
    await waitFor(() => {
      expect(fetch).toHaveBeenCalledTimes(2);
    });
    expect(bodyOf(fetch.mock.calls[1]?.[1]).history).toEqual([]);
  });

  it("shows a missing terminal event as an error, not a complete answer", async () => {
    setup(() => ndjsonResponse(ndjson([START, { type: "delta", text: "looks complete" }])));
    ask("q");
    expect(await screen.findByText(/This answer is incomplete\./)).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe(CHAT_ERROR_MESSAGES.protocol);
  });

  it("maps a rate limit before the stream and a lost connection to fixed messages", async () => {
    let call = 0;
    setup(() => {
      call += 1;
      if (call === 1) return jsonResponse({ detail: "slow down" }, 429);
      return Promise.reject(new TypeError("Failed to fetch"));
    });
    ask("one");
    expect(await screen.findByText(CHAT_ERROR_MESSAGES.rate_limited, { selector: ".chat-note" })).toBeTruthy();
    ask("two");
    expect(await screen.findByText(CHAT_ERROR_MESSAGES.network, { selector: ".chat-note" })).toBeTruthy();
  });

  it("explains a 403", async () => {
    setup(() => jsonResponse({}, 403));
    ask("q");
    expect(await screen.findByText(/Your role does not include Ask LightHouse/, { selector: ".chat-note" })).toBeTruthy();
  });

  it("stops an answer on request", async () => {
    const stream = controlledStream();
    const { fetch } = setup(() => stream.response);
    ask("q");
    stream.send([START, { type: "delta", text: "partial" }]);
    expect(await screen.findByText("partial")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Stop answering" }));
    expect(screen.getByText("Stopped. This answer is incomplete.")).toBeTruthy();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    await waitFor(() => {
      expect(stream.cancelled).toHaveBeenCalled();
    });
  });

  it("aborts the previous answer when a new question is asked", async () => {
    const first = controlledStream();
    let call = 0;
    const { fetch } = setup(() => {
      call += 1;
      return call === 1 ? first.response : ndjsonResponse(ndjson([START, { type: "delta", text: "second answer" }, DONE]));
    });
    ask("first");
    first.send([START, { type: "delta", text: "first partial" }]);
    expect(await screen.findByText("first partial")).toBeTruthy();

    ask("second");
    expect(await screen.findByText("second answer")).toBeTruthy();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    expect(screen.getByText("Stopped. This answer is incomplete.")).toBeTruthy();
    // The stopped answer's stream was cancelled; a late delta changes nothing.
    await waitFor(() => {
      expect(first.cancelled).toHaveBeenCalled();
    });
    first.send([{ type: "delta", text: " LATE" }]);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(screen.queryByText(/LATE/)).toBeNull();
  });

  it("aborts the stream on unmount", async () => {
    const stream = controlledStream();
    const { fetch, unmount } = setup(() => stream.response);
    ask("q");
    await waitFor(() => {
      expect(fetch).toHaveBeenCalled();
    });
    unmount();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it("validates the question before sending", () => {
    const { fetch } = setup(() => jsonResponse({}, 500));
    ask("   ");
    expect(screen.getByRole("alert").textContent).toBe("Type a question first.");
    expect(screen.getByLabelText("Your question").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByLabelText("Your question").getAttribute("maxlength")).toBe("2000");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("clears the conversation", async () => {
    setup(() => ndjsonResponse(ndjson([START, { type: "delta", text: "an answer" }, DONE])));
    ask("q");
    expect(await screen.findByText("an answer")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "New conversation" }));
    expect(screen.queryByText("an answer")).toBeNull();
  });

  it("keeps the conversation out of web storage", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    setup(() => ndjsonResponse(ndjson([START, { type: "delta", text: "an answer" }, DONE])));
    ask("q");
    expect(await screen.findByText("an answer")).toBeTruthy();
    expect(setItem).not.toHaveBeenCalled();
  });
});
