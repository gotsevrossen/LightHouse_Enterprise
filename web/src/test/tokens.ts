// Builds JWT-shaped test tokens at run time from small synthetic JSON objects.
//
// A JWT-shaped string literal in the source trips the secret scanner (gitleaks `jwt` rule)
// in pre-commit and CI. Rather than allowlisting it, tests assemble the token here, so no
// such literal exists in the repository. The result is not signed and grants nothing.

function base64url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** header.payload.signature, each part base64url-encoded, with a dummy signature. */
export function makeJwtShapedToken(
  payload: Record<string, unknown> = { sub: "test-user" },
  header: Record<string, unknown> = { alg: "HS256", typ: "JWT" },
): string {
  return [base64url(JSON.stringify(header)), base64url(JSON.stringify(payload)), base64url("test-signature")].join(".");
}
