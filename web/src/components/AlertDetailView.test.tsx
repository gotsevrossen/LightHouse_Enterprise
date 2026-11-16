import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createApiClient, type AlertDetail } from "../api.ts";
import { jsonResponse, makeAlertDetail, makeAnalystDetail, routedFetch, signedInAuth } from "../test/fixtures.ts";
import { AlertDetailView } from "./AlertDetailView.tsx";

const ID = "alert-1";

function setup(
  route: Parameters<typeof routedFetch>[0][string],
  options: { canChangeStatus?: boolean; chatAvailable?: boolean } = {},
) {
  const fetch = routedFetch({ [`/api/alerts/${ID}`]: route, "/api/chat/stream": () => jsonResponse({}, 503) });
  const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
  const onBack = vi.fn();
  const onUpdated = vi.fn<(alert: AlertDetail) => void>();
  const view = render(
    <AlertDetailView
      api={api}
      alertId={ID}
      canChangeStatus={options.canChangeStatus ?? false}
      chatAvailable={options.chatAvailable ?? false}
      onBack={onBack}
      onUpdated={onUpdated}
    />,
  );
  return { ...view, fetch, onBack, onUpdated };
}

function isPatch(init: RequestInit | undefined): boolean {
  return init?.method === "PATCH";
}

describe("AlertDetailView", () => {
  it("shows the plain-English view first, with severity, source rating and confidence in words", async () => {
    setup(() => jsonResponse(makeAlertDetail({ severity: "high", source_severity: "medium", confidence: 0.3 })));

    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Suspicious sign-in from an unfamiliar location");
    await waitFor(() => {
      expect(document.activeElement).toBe(heading);
    });
    expect(screen.getByText("Severity:", { exact: false }).parentElement?.textContent).toContain("High");
    expect(screen.getByText("Source rated it Medium")).toBeTruthy();
    expect(screen.getByText("A user signed in from a country they have not used before.")).toBeTruthy();
    expect(screen.getByText("Confirm with the user that the sign-in was theirs.")).toBeTruthy();
    expect(screen.getByText("Confidence").nextElementSibling?.textContent).toBe("Low");
    expect(screen.getByText("Category").nextElementSibling?.textContent).toBe("Initial access");
  });

  it("explains why an alert needs review in plain English", async () => {
    setup(() =>
      jsonResponse(makeAlertDetail({ needs_human_review: true, review_reason: "refusal", summary: null, confidence: null })),
    );
    expect(await screen.findByText("Needs human review")).toBeTruthy();
    expect(screen.getByText(/declined to assess this alert/)).toBeTruthy();
    expect(screen.getByText("No summary yet.")).toBeTruthy();
    expect(screen.getByText("Confidence").nextElementSibling?.textContent).toBe("Not rated");
  });

  it("uses a generic sentence for a review reason it does not know, never the raw value", async () => {
    setup(() => jsonResponse(makeAlertDetail({ needs_human_review: true, review_reason: "<b>call 555-0100</b>" })));
    expect(await screen.findByText("LightHouse flagged this alert for a person to check.")).toBeTruthy();
    expect(document.body.textContent).not.toContain("555-0100");
  });

  it("shows no analyst view for the viewer shape", async () => {
    setup(() => jsonResponse(makeAlertDetail()));
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByText("Analyst view")).toBeNull();
    expect(screen.queryByText("Evidence")).toBeNull();
  });

  it("shows reasoning and evidence in a collapsed analyst view for the analyst shape", async () => {
    const { container } = setup(() => jsonResponse(makeAnalystDetail()));
    const summary = await screen.findByText("Analyst view");
    const details = summary.closest("details");
    expect(details?.open).toBe(false);
    fireEvent.click(summary);

    expect(screen.getByText("Written by AI. It can be wrong.")).toBeTruthy();
    expect(screen.getByText("The sign-in came from a country this user has not used before.")).toBeTruthy();
    const list = container.querySelector("dl.evidence");
    expect(list).not.toBeNull();
    const terms = [...(list?.querySelectorAll("dt") ?? [])].map((dt) => dt.textContent);
    expect(terms).toEqual(["user_principal", "country", "sign_in_count", "mfa", "ip_addresses", "device"]);
    const values = [...(list?.querySelectorAll("dd") ?? [])].map((dd) => dd.textContent);
    expect(values).toEqual(["user@example.test", "Elsewhere", "3", "no", "192.0.2.10192.0.2.11", "empty"]);
    expect(within(list as HTMLElement).getAllByRole("listitem")).toHaveLength(2);
  });

  it("renders hostile text as literal text everywhere, including evidence keys and values", async () => {
    const html = '<img src=x onerror="window.__pwned=1">';
    const { container } = setup(() =>
      jsonResponse(
        makeAnalystDetail({
          title: html,
          summary: "<script>window.__pwned=1</script>",
          recommended_action: '<a href="javascript:alert(1)">fix</a>',
          category: "<b>cat</b>",
          source: "<i>src</i>",
          reasoning: "<iframe src=javascript:alert(1)></iframe>",
          evidence: {
            [html]: "<svg onload=alert(1)>",
            "<a href=//evil.example.test>k</a>": ["<style>body{display:none}</style>", "javascript:alert(1)"],
            __proto__note: "[click here](https://evil.example.test)",
          },
        }),
      ),
    );
    fireEvent.click(await screen.findByText("Analyst view"));

    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(html);
    expect(screen.getByText("<script>window.__pwned=1</script>")).toBeTruthy();
    expect(screen.getByText(html, { selector: "dt" })).toBeTruthy();
    expect(screen.getByText("<svg onload=alert(1)>")).toBeTruthy();
    expect(screen.getByText("[click here](https://evil.example.test)")).toBeTruthy();
    for (const tag of ["img", "script", "a", "iframe", "svg", "style", "b", "i"]) {
      expect(container.querySelector(tag), tag).toBeNull();
    }
    expect(container.querySelector("[onerror], [onload], [href], [src]")).toBeNull();
    expect((window as unknown as { __pwned?: unknown }).__pwned).toBeUndefined();
  });

  it("shortens long evidence values with a keyboard-operable toggle", async () => {
    const long = `${"A".repeat(300)}END`;
    setup(() => jsonResponse(makeAnalystDetail({ evidence: { command_line: long } })));
    fireEvent.click(await screen.findByText("Analyst view"));

    expect(screen.queryByText(long)).toBeNull();
    const toggle = screen.getByRole("button", { name: "Show all 303 characters" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    expect(screen.getByText(long)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Show less" }).getAttribute("aria-expanded")).toBe("true");
  });

  it("hides status changes from viewers", async () => {
    setup(() => jsonResponse(makeAlertDetail()), { canChangeStatus: false });
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByLabelText("Change status")).toBeNull();
  });

  it("changes the status only after the server confirms", async () => {
    let release: () => void = () => undefined;
    const { fetch, onUpdated } = setup(
      (_url, init) =>
        isPatch(init)
          ? new Promise<Response>((resolve) => {
              release = () => {
                resolve(jsonResponse(makeAnalystDetail({ status: "investigating" })));
              };
            })
          : jsonResponse(makeAnalystDetail({ status: "new" })),
      { canChangeStatus: true },
    );

    const select = await screen.findByLabelText<HTMLSelectElement>("Change status");
    expect(select.value).toBe("new");
    const save = screen.getByRole("button", { name: "Save status" });
    expect((save as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(select, { target: { value: "investigating" } });
    fireEvent.click(save);

    expect(await screen.findByText("Saving the new status…")).toBeTruthy();
    // Not yet confirmed: the stored status still shows the old value.
    expect(screen.getByText("Status").nextElementSibling?.textContent).toBe("New");
    expect(onUpdated).not.toHaveBeenCalled();

    release();
    expect(await screen.findByText("Status saved as Investigating.")).toBeTruthy();
    expect(screen.getByText("Status").nextElementSibling?.textContent).toBe("Investigating");
    expect(onUpdated).toHaveBeenCalledTimes(1);
    const patch = fetch.mock.calls.find(([, init]) => isPatch(init));
    expect(patch?.[1]?.body).toBe(JSON.stringify({ status: "investigating" }));
  });

  it("explains a 403 and leaves the status as it was", async () => {
    const { onUpdated } = setup(
      (_url, init) => (isPatch(init) ? jsonResponse({ detail: "forbidden" }, 403) : jsonResponse(makeAnalystDetail({ status: "new" }))),
      { canChangeStatus: true },
    );
    const select = await screen.findByLabelText<HTMLSelectElement>("Change status");
    fireEvent.change(select, { target: { value: "resolved" } });
    fireEvent.click(screen.getByRole("button", { name: "Save status" }));

    const error = await screen.findByRole("alert");
    expect(error.textContent).toContain("Your role does not allow changing the status");
    expect(error.textContent).toContain("The status was not changed.");
    expect(select.value).toBe("new");
    expect(screen.getByText("Status").nextElementSibling?.textContent).toBe("New");
    expect(onUpdated).not.toHaveBeenCalled();
  });

  it("shows an error state for a server failure", async () => {
    const { container } = setup(
      (_url, init) => (isPatch(init) ? jsonResponse({}, 500) : jsonResponse(makeAnalystDetail({ status: "new" }))),
      { canChangeStatus: true },
    );
    fireEvent.change(await screen.findByLabelText("Change status"), { target: { value: "dismissed" } });
    fireEvent.click(screen.getByRole("button", { name: "Save status" }));
    expect((await screen.findByRole("alert")).textContent).toContain("error 500");
    expect(container.textContent).not.toContain("Status saved");
  });

  it("shows not-found and malformed responses as errors with a retry", async () => {
    let calls = 0;
    setup(() => {
      calls += 1;
      return calls === 1 ? jsonResponse({ detail: "not found" }, 404) : jsonResponse(makeAlertDetail({ confidence: 7 }));
    });
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("could not find this alert");
    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    expect((await screen.findByRole("alert")).textContent).toContain("format the console does not recognise");
  });

  it("goes back with a real button", async () => {
    const { onBack } = setup(() => jsonResponse(makeAlertDetail()));
    const back = await screen.findByRole("button", { name: "Back to alerts" });
    expect(back.getAttribute("type")).toBe("button");
    fireEvent.click(back);
    expect(onBack).toHaveBeenCalled();
  });

  it("shows the alert-scoped chat only when chat is available", async () => {
    const first = setup(() => jsonResponse(makeAlertDetail()), { chatAvailable: false });
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByRole("heading", { name: "Ask LightHouse" })).toBeNull();
    first.unmount();

    setup(() => jsonResponse(makeAlertDetail()), { chatAvailable: true });
    expect(await screen.findByRole("heading", { name: "Ask LightHouse" })).toBeTruthy();
    expect(screen.getByText(/Questions here are about this alert/)).toBeTruthy();
  });

  it("aborts the request when it unmounts", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() => new Promise<Response>(() => undefined));
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    const { unmount } = render(
      <AlertDetailView api={api} alertId={ID} canChangeStatus chatAvailable={false} onBack={vi.fn()} onUpdated={vi.fn()} />,
    );
    await waitFor(() => {
      expect(fetch).toHaveBeenCalled();
    });
    unmount();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
});
