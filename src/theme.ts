import { alpha, createTheme, type PaletteMode } from "@mui/material/styles";

export const buildTheme = (mode: PaletteMode) => createTheme({
  palette: {
    mode,
    primary: { main: mode === "dark" ? "#A8C7FA" : "#2E5BFF" },
    secondary: { main: mode === "dark" ? "#B8C4FF" : "#5265C4" },
    success: { main: "#25A56A" }, warning: { main: "#F0A020" }, error: { main: "#DC4C64" },
    background: { default: mode === "dark" ? "#0B0F17" : "#F5F7FB", paper: mode === "dark" ? "#141A24" : "#FFFFFF" },
  },
  shape: { borderRadius: 12 },
  typography: {
    fontFamily: 'Roboto, "Noto Sans SC", "Microsoft YaHei", sans-serif',
    h5: { fontWeight: 700, letterSpacing: "-0.02em" }, h6: { fontWeight: 650 }, button: { textTransform: "none", fontWeight: 600 },
  },
  components: {
    MuiCssBaseline: { styleOverrides: { body: { overflow: "hidden" }, "*": { scrollbarWidth: "thin" } } },
    MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
    MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { borderRadius: 10, minHeight: 36 } } },
    MuiChip: { styleOverrides: { root: { borderRadius: 8 } } },
    MuiListItemButton: { styleOverrides: { root: ({ theme }) => ({ borderRadius: 10, marginInline: 8, "&.Mui-selected": { backgroundColor: alpha(theme.palette.primary.main, .12) } }) } },
  },
});
