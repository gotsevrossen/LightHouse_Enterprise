import { ApiError } from "../api.ts";

/** Plain-English explanation of a failed request, with what to do next. */
export function describeError(error: unknown, subject: string): string {
  if (!(error instanceof ApiError)) {
    return `Something went wrong while loading ${subject}. Try again.`;
  }
  switch (error.kind) {
    case "forbidden":
      return `Your role does not include access to ${subject}. Ask an admin in your organisation to change it.`;
    case "network":
      return `The console could not reach the LightHouse service to load ${subject}. Check your connection, then try again.`;
    case "invalid_response":
      return `The LightHouse service sent ${subject} in a format the console does not recognise, so nothing is shown. Try again. If this keeps happening, report it to your LightHouse contact.`;
    case "http":
      return error.status !== null && error.status >= 500
        ? `The LightHouse service had a problem loading ${subject} (error ${error.status}). Try again in a moment.`
        : `The LightHouse service refused the request for ${subject} (error ${error.status ?? "unknown"}). Try again.`;
    case "signed_out":
    case "unauthorized":
      return "Your session has ended. Sign in again to continue.";
  }
}
