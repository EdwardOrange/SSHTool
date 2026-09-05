import { alpha, createTheme, type PaletteMode } from "@mui/material/styles";

export const buildTheme = (mode: PaletteMode) => createTheme({
  palette: {
    mode,
    primary: { main: mode === "dark" ? "#A8C7FA" : "#2E5BFF" },
    secondary: { main: mode === "dark" ? "#B8C4FF" : "#5265C4" },
    success: { main: "#25A56A" }, warning: { main: "#F0A020" }, error: { main: "#DC4C64" },
    background: { default: mode === "dark" ? "#0B0F17" : "#F5F7FB", paper: mode === "dark" ? "#141A24" : "#FFFFFF" },
    divider: mode === "dark" ? alpha("#D8E2F2", .14) : alpha("#334155", .14),
  },
  shape: { borderRadius: 12 },
  typography: {
    fontFamily: 'Roboto, "Noto Sans SC", "Microsoft YaHei", sans-serif',
    h5: { fontWeight: 700, letterSpacing: "-0.02em" }, h6: { fontWeight: 650 }, button: { textTransform: "none", fontWeight: 600 },
  },
  components: {
    MuiCssBaseline: { styleOverrides: { body: { overflow: "hidden", backgroundColor: mode === "dark" ? "#0B0F17" : "#F5F7FB" }, "*": { scrollbarWidth: "thin" }, "*:focus-visible": { outline: `3px solid ${alpha(mode === "dark" ? "#A8C7FA" : "#2E5BFF", .45)}`, outlineOffset: 2 } } },
    MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
    MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { borderRadius: 10, minHeight: 40, transition: "background-color 140ms ease, border-color 140ms ease, transform 140ms ease", "&:active": { transform: "scale(.98)" } } } },
    MuiIconButton: { styleOverrides: { root: { minWidth: 40, minHeight: 40 } } },
    MuiChip: { styleOverrides: { root: { borderRadius: 8, fontWeight: 500 } } },
    MuiTextField: { defaultProps: { variant: "outlined" }, styleOverrides: { root: { "& .MuiOutlinedInput-root": { borderRadius: 12 } } } },
    MuiTabs: { styleOverrides: { indicator: { height: 3, borderRadius: 3 }, flexContainer: { gap: 4 } } },
    MuiTableCell: { styleOverrides: { root: { borderColor: mode === "dark" ? alpha("#D8E2F2", .1) : alpha("#334155", .1) } }, },
    MuiDialog: { styleOverrides: { paper: { borderRadius: 20 } } },
    MuiListItemButton: { styleOverrides: { root: ({ theme }) => ({ borderRadius: 10, marginInline: 8, "&.Mui-selected": { backgroundColor: alpha(theme.palette.primary.main, .12) } }) } },
  },
});
