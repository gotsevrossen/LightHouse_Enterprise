import type { ReactNode } from "react";
import type { Me, Role } from "../api.ts";

const ROLE_LABELS: Record<Role, string> = {
  viewer: "Viewer",
  analyst: "Analyst",
  responder: "Responder",
  admin: "Admin",
};

interface AppShellProps {
  /** Null while the account is loading or could not be loaded. */
  readonly me: Me | null;
  readonly onSignOut: () => void;
  readonly children: ReactNode;
}

// The role shown here is for orientation only. What a user may do is decided by the API on
// every request; hiding or showing a control in the console is not access control.
export function AppShell({ me, onSignOut, children }: AppShellProps) {
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="shell-header">
        <div className="shell-header-inner">
          <p className="product-name">LightHouse Enterprise</p>
          <div className="account">
            {me !== null && (
              <dl className="account-details">
                <div>
                  <dt>Role</dt>
                  <dd>{ROLE_LABELS[me.role]}</dd>
                </div>
                <div>
                  <dt>Tenant</dt>
                  <dd className="account-tenant">{me.tenant_id}</dd>
                </div>
              </dl>
            )}
            <button type="button" className="button button-quiet" onClick={onSignOut}>
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main id="main" className="shell-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
