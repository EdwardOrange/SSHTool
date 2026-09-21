import React from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, useMediaQuery } from "@mui/material";
import { buildTheme } from "./theme";
import "./i18n";
import "./styles.css";
import App from "./App";
import AppErrorBoundary from "./components/AppErrorBoundary";
import { readLocalPreference } from "./localPreferences";

function Root() {
  React.useEffect(() => {
    const preventBrowserMenu = (event: MouseEvent) => event.preventDefault();
    document.addEventListener("contextmenu", preventBrowserMenu);
    return () => document.removeEventListener("contextmenu", preventBrowserMenu);
  }, []);
  const prefersDark = useMediaQuery("(prefers-color-scheme: dark)");
  const [mode, setMode] = React.useState<"light" | "dark">(() => {
    const saved = readLocalPreference("theme");
    return saved === "light" || saved === "dark" ? saved : prefersDark ? "dark" : "light";
  });
  const theme = React.useMemo(() => buildTheme(mode), [mode]);
  return <ThemeProvider theme={theme}><CssBaseline /><App mode={mode} setMode={setMode} /></ThemeProvider>;
}

// A terminal session is an external, stateful resource. React StrictMode intentionally
// remounts effects in development, which would create and immediately close a second
// remote PTY. Keep the production and desktop development lifecycle identical.
ReactDOM.createRoot(document.getElementById("root")!).render(<AppErrorBoundary><Root /></AppErrorBoundary>);
