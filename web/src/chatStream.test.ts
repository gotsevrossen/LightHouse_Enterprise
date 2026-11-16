import { describe, expect, it, vi } from "vitest";
import { CHAT_MAX_ANSWER_LENGTH, CHAT_MAX_LINE_LENGTH, readChatStream } from "./api.ts";
import { ndjson, streamOf } from "./test/fixtures.ts";

async function read(chunks: readonly (string | Uint8Array)[]) {
  const deltas: string[] = [];
  const outcome = await readChatStream(streamOf(chunks), (text) => deltas.push(text));
  return { outcome, deltas, text: deltas.join("") };
}

const START = { type: "start" };
const DONE = { type: "done" };

describe("readChatStream", () => {
  it("reads start, deltas and done", async () => {
    const { outcome, deltas } = await read([
      ndjson([START, { type: "delta", text: "Hello" }, { type: "delta", text: ", world" }, DONE]),
    ]);
    expect(outcome).toEqual({ kind: "done" });
    expect(deltas).toEqual(["Hello", ", world"]);
  });

  it("joins lines split across chunks, including inside a multi-byte character", async () => {
    const body = ndjson([START, { type: "delta", text: "Grüße – ✓" }, DONE]);
    const bytes = new TextEncoder().encode(body);
    // One byte per chunk splits every multi-byte character and every line.
    const chunks = Array.from(bytes, (byte) => new Uint8Array([byte]));
    const { outcome, text } = await read(chunks);
    expect(outcome).toEqual({ kind: "done" });
    expect(text).toBe("Grüße – ✓");
  });

  it("handles many events in one chunk, CRLF line ends and blank lines", async () => {
    const lines = [START, ...Array.from({ length: 50 }, (_, i) => ({ type: "delta", text: String(i % 10) })), DONE];
    const body = lines.map((event) => `${JSON.stringify(event)}\r\n\r\n`).join("");
    const { outcome, text } = await read([body]);
    expect(outcome).toEqual({ kind: "done" });
    expect(text).toBe("0123456789".repeat(5));
  });

  it("accepts a terminal event with no final newline", async () => {
    const { outcome } = await read([`${JSON.stringify(START)}\n${JSON.stringify(DONE)}`]);
    expect(outcome).toEqual({ kind: "done" });
  });

  it("ends with the server's error code", async () => {
    for (const code of ["budget_exceeded", "rate_limited", "declined", "unavailable", "too_long", "internal"]) {
      const { outcome } = await read([ndjson([START, { type: "error", code }])]);
      expect(outcome).toEqual({ kind: "error", code });
    }
  });

  it("maps an unknown error code to internal", async () => {
    const { outcome } = await read([ndjson([START, { type: "error", code: "<script>" }])]);
    expect(outcome).toEqual({ kind: "error", code: "internal" });
  });

  it.each([
    ["an invalid JSON line", [`${JSON.stringify(START)}\n{not json\n`]],
    ["an unknown event type", [ndjson([START, { type: "tool_call", name: "run_shell" }, DONE])]],
    ["a delta before start", [ndjson([{ type: "delta", text: "x" }, DONE])]],
    ["a second start", [ndjson([START, START, DONE])]],
    ["a delta with non-string text", [ndjson([START, { type: "delta", text: { html: "<b>" } }, DONE])]],
    ["a JSON value that is not an object", [`${JSON.stringify(START)}\n["delta"]\n`]],
    ["a missing terminal event", [ndjson([START, { type: "delta", text: "half an ans" }])]],
    ["an empty body", []],
    ["invalid UTF-8", [new Uint8Array([0x7b, 0xff, 0xfe, 0x7d, 0x0a])]],
  ])("ends in a protocol error for %s", async (_label, chunks) => {
    const { outcome } = await read(chunks);
    expect(outcome).toEqual({ kind: "error", code: "protocol" });
  });

  it("stops at an oversized line without buffering it all", async () => {
    const huge = "a".repeat(CHAT_MAX_LINE_LENGTH + 10);
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        if (pulled === 1) controller.enqueue(new TextEncoder().encode(ndjson([START])));
        // Never sends a newline: an endless line.
        else controller.enqueue(new TextEncoder().encode(huge));
      },
    });
    const outcome = await readChatStream(body, () => undefined);
    expect(outcome).toEqual({ kind: "error", code: "protocol" });
    expect(pulled).toBeLessThan(5);
  });

  it("stops when the answer grows past the cap", async () => {
    const piece = "b".repeat(8_000);
    const events = [START, ...Array.from({ length: CHAT_MAX_ANSWER_LENGTH / 8_000 + 1 }, () => ({ type: "delta", text: piece })), DONE];
    const { outcome } = await read([ndjson(events)]);
    expect(outcome).toEqual({ kind: "error", code: "protocol" });
  });

  it("ignores anything after the terminal event and cancels the stream", async () => {
    const cancel = vi.fn();
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(ndjson([START, { type: "delta", text: "ok" }, DONE, { type: "delta", text: "late" }])));
      },
      cancel,
    });
    const deltas: string[] = [];
    const outcome = await readChatStream(body, (text) => deltas.push(text));
    expect(outcome).toEqual({ kind: "done" });
    expect(deltas).toEqual(["ok"]);
    expect(cancel).toHaveBeenCalled();
  });

  it("reports a stream that fails mid-answer as a network error", async () => {
    let step = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        step += 1;
        if (step === 1) controller.enqueue(new TextEncoder().encode(ndjson([START, { type: "delta", text: "par" }])));
        else controller.error(new TypeError("network reset"));
      },
    });
    const outcome = await readChatStream(body, () => undefined);
    expect(outcome).toEqual({ kind: "error", code: "network" });
  });

  it("rejects with the abort reason and cancels the stream when aborted", async () => {
    const cancel = vi.fn();
    let push: (text: string) => void = () => undefined;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        push = (text) => {
          controller.enqueue(new TextEncoder().encode(text));
        };
      },
      cancel,
    });
    const controller = new AbortController();
    const deltas: string[] = [];
    const pending = readChatStream(body, (text) => deltas.push(text), controller.signal);
    push(ndjson([START, { type: "delta", text: "first" }]));
    await vi.waitFor(() => {
      expect(deltas).toEqual(["first"]);
    });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(cancel).toHaveBeenCalled();
  });

  it("does not read at all when already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const onDelta = vi.fn();
    await expect(readChatStream(streamOf([ndjson([START, DONE])]), onDelta, controller.signal)).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(onDelta).not.toHaveBeenCalled();
  });
});
