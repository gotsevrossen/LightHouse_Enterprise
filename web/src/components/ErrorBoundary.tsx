import { Component, type ReactNode } from "react";

interface Props {
  readonly children: ReactNode;
}

interface State {
  readonly failed: boolean;
}

/**
 * Last line of defence against a white screen. Responses are validated in api.ts, so this
 * should only catch programming errors. It deliberately does not log the error: error
 * messages can carry customer text, and the console has no scrubbing logger yet.
 */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  override render() {
    if (!this.state.failed) {
      return this.props.children;
    }
    return (
      <div role="alert" className="notice notice-error">
        <h2 className="notice-title">This part of the console stopped working</h2>
        <p>Nothing was changed in your organisation. Reload the page to try again.</p>
        <button
          type="button"
          className="button"
          onClick={() => {
            window.location.reload();
          }}
        >
          Reload page
        </button>
      </div>
    );
  }
}
