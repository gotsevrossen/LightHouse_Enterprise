import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createApiClient, type ApiClient } from "../api.ts";
import { jsonResponse, makeAlert, requestedUrls, routedFetch, signedInAuth } from "../test/fixtures.ts";
import { AlertsQueue, PAGE_SIZE } from "./AlertsQueue.tsx";

function apiWith(alertsRoute: (url: URL) => Response): { api: ApiClient; fetch: ReturnType<typeof routedFetch> } {
  const fetch = routedFetch({ "/api/alerts": alertsRoute });
  return { api: createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch }), fetch };
}

describe("AlertsQueue", () => {
  it("shows a loading notice, then the alerts", async () => {
    const { api, fetch } = apiWith(() =>
      jsonResponse({
        items: [makeAlert(), makeAlert({ id: "alert-2", title: "Malware blocked on a laptop", severity: "low", source_severity: "low" })],
        next_cursor: null,
      }),
    );
    render(<AlertsQueue api={api} />);

    expect(screen.getByRole("status")).toHaveProperty("textContent", "Loading alerts…");

    const list = await screen.findByRole("list");
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(screen.getByRole("heading", { name: "Suspicious sign-in from an unfamiliar location" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("Showing 2 alerts.");

    const [, init] = fetch.mock.calls[0] ?? [];
    expect(new URL(requestedUrls(fetch)[0] ?? "", "http://x.test").searchParams.get("limit")).toBe(String(PAGE_SIZE));
    expect(init?.method).toBe("GET");
  });

  it("shows severity as a text label, not colour alone", async () => {
    const { api } = apiWith(() =>
      jsonResponse({
        items: [
          makeAlert({ id: "a", severity: "critical", source_severity: "low" }),
          makeAlert({ id: "b", severity: "unknown", source_severity: "unknown" }),
        ],
        next_cursor: null,
      }),
    );
    render(<AlertsQueue api={api} />);

    const items = within(await screen.findByRole("list")).getAllByRole("listitem");
    expect(items[0]?.textContent).toContain("Severity: Critical");
    expect(items[0]?.textContent).toContain("Source rated it Low");
    expect(items[1]?.textContent).toContain("Severity: Unknown");
    expect(items[1]?.textContent).not.toContain("Source rated it");
  });

  it("flags alerts that need human review in words", async () => {
    const { api } = apiWith(() =>
      jsonResponse({ items: [makeAlert({ needs_human_review: true, summary: null, recommended_action: null })], next_cursor: null }),
    );
    render(<AlertsQueue api={api} />);

    expect(await screen.findByText("Needs human review")).toBeTruthy();
    expect(screen.getByText("No summary yet.")).toBeTruthy();
    expect(screen.queryByText("Next step:")).toBeNull();
  });

  it("renders attacker-controlled alert text as literal text", async () => {
    const payload = '<img src=x onerror="window.__pwned=1">';
    const { api } = apiWith(() =>
      jsonResponse({
        items: [
          makeAlert({
            title: payload,
            summary: `<script>window.__pwned=1</script>`,
            recommended_action: `<a href="javascript:alert(1)">click</a>`,
            source: `<b>bold</b>`,
            status: `<i>x</i>`,
          }),
        ],
        next_cursor: null,
      }),
    );
    const { container } = render(<AlertsQueue api={api} />);

    const heading = await screen.findByRole("heading", { level: 2 });
    expect(heading.textContent).toBe(payload);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
    expect((window as unknown as { __pwned?: unknown }).__pwned).toBeUndefined();
  });

  it("shows an empty state", async () => {
    const { api } = apiWith(() => jsonResponse({ items: [], next_cursor: null }));
    render(<AlertsQueue api={api} />);

    await waitFor(() => {
      expect(screen.getByRole("status").textContent).toMatch(/^No alerts to review\./);
    });
    expect(screen.queryByRole("list")).toBeNull();
  });

  it("shows an error state with a retry for a server error", async () => {
    let calls = 0;
    const { api } = apiWith(() => {
      calls += 1;
      return calls === 1 ? jsonResponse({ detail: "boom" }, 500) : jsonResponse({ items: [makeAlert()], next_cursor: null });
    });
    render(<AlertsQueue api={api} />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("error 500");

    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("list")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the error state, not a broken list, for a corrupt response", async () => {
    const { api } = apiWith(() =>
      jsonResponse({ items: [makeAlert(), makeAlert({ id: "bad", severity: "catastrophic" })], next_cursor: null }),
    );
    render(<AlertsQueue api={api} />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("format the console does not recognise");
    expect(screen.queryByRole("list")).toBeNull();
  });

  it("loads more alerts with the cursor and skips duplicates", async () => {
    const { api, fetch } = apiWith((url) =>
      url.searchParams.get("cursor") === "page-2"
        ? jsonResponse({ items: [makeAlert({ id: "alert-1" }), makeAlert({ id: "alert-3", title: "Third alert" })], next_cursor: null })
        : jsonResponse({ items: [makeAlert({ id: "alert-1" }), makeAlert({ id: "alert-2", title: "Second alert" })], next_cursor: "page-2" }),
    );
    render(<AlertsQueue api={api} />);

    const button = await screen.findByRole("button", { name: "Load more alerts" });
    expect(screen.getByRole("status").textContent).toBe("Showing 2 alerts. More are available.");
    fireEvent.click(button);

    expect(await screen.findByRole("heading", { name: "Third alert" })).toBeTruthy();
    expect(within(screen.getByRole("list")).getAllByRole("listitem")).toHaveLength(3);
    expect(screen.queryByRole("button", { name: "Load more alerts" })).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("keeps loaded alerts when loading more fails", async () => {
    const { api } = apiWith((url) =>
      url.searchParams.has("cursor") ? jsonResponse({}, 502) : jsonResponse({ items: [makeAlert()], next_cursor: "more" }),
    );
    render(<AlertsQueue api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Load more alerts" }));

    expect((await screen.findByRole("alert")).textContent).toContain("more alerts");
    expect(within(screen.getByRole("list")).getAllByRole("listitem")).toHaveLength(1);
  });

  it("is keyboard operable: controls are real buttons", async () => {
    const { api } = apiWith(() => jsonResponse({ items: [makeAlert()], next_cursor: "more" }));
    render(<AlertsQueue api={api} />);
    const refresh = await screen.findByRole("button", { name: "Refresh" });
    const more = screen.getByRole("button", { name: "Load more alerts" });
    for (const button of [refresh, more]) {
      expect(button.tagName).toBe("BUTTON");
      expect(button.getAttribute("type")).toBe("button");
    }
  });

  it("does not update state after unmounting", async () => {
    let resolve: (response: Response) => void = () => undefined;
    const fetch = vi.fn<typeof globalThis.fetch>(
      () =>
        new Promise<Response>((r) => {
          resolve = r;
        }),
    );
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    const { unmount } = render(<AlertsQueue api={api} />);
    await waitFor(() => {
      expect(fetch).toHaveBeenCalled();
    });
    const init = fetch.mock.calls[0]?.[1];
    unmount();
    expect(init?.signal?.aborted).toBe(true);
    resolve(jsonResponse({ items: [], next_cursor: null }));
  });
});
