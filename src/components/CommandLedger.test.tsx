// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../store";
import CommandLedger from "./CommandLedger";

vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
afterEach(cleanup);

describe("command details", () => {
  it("shows stderr alongside stdout so partial success does not hide the failure", () => {
    useAppStore.setState({ settings: undefined, commandPanelOpen: true, commands: [{
      id: "mixed", timestamp: new Date().toISOString(), source: "system", command: "partial-command",
      stdout: "first step succeeded", stderr: "second step failed", durationMs: 5, status: "error", repeatCount: 1,
    }] });
    render(<CommandLedger/>);
    fireEvent.click(screen.getByText("$ partial-command"));
    expect(screen.getByText(/first step succeeded[\s\S]*second step failed/)).toBeTruthy();
  });
});
