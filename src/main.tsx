import React from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, useMediaQuery } from "@mui/material";
import { buildTheme } from "./theme";
import "./i18n";
import "./styles.css";
import App from "./App";
import AppErrorBoundary from "./components/AppErrorBoundary";

function Root() {
  React.useEffect(() => {
    const preventBrowserMenu = (event: MouseEvent) => event.preventDefault();
    document.addEventListener("contextmenu", preventBrowserMenu);
    return () => document.removeEventListener("contextmenu", preventBrowserMenu);
  }, []);
  const prefersDark = useMediaQuery("(prefers-color-scheme: dark)");
  const [mode, setMode] = React.useState<"light" | "dark">(() => (localStorage.getItem("theme") as "light" | "dark") || (prefersDark ? "dark" : "light"));
  const theme = React.useMemo(() => buildTheme(mode), [mode]);
  const toggle = () => setMode((value) => { const next = value === "dark" ? "light" : "dark"; localStorage.setItem("theme", next); return next; });
  return <ThemeProvider theme={theme}><CssBaseline /><App mode={mode} toggleMode={toggle} /></ThemeProvider>;
}

// A terminal session is an external, stateful resource. React StrictMode intentionally
// remounts effects in development, which would create and immediately close a second
// remote PTY. Keep the production and desktop development lifecycle identical.
ReactDOM.createRoot(document.getElementById("root")!).render(<AppErrorBoundary><Root /></AppErrorBoundary>);
