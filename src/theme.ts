import { alpha, createTheme, type PaletteMode } from "@mui/material/styles";

// Material 3 semantic color roles, paired for accessible light and dark surfaces.
export const materialColors = (mode: PaletteMode) => mode === "dark" ? {
  primary: "#ADC6FF", onPrimary: "#102F60", primaryContainer: "#2B4678", onPrimaryContainer: "#D8E2FF",
  secondary: "#BFC6DC", onSecondary: "#293041", secondaryContainer: "#3F4759", onSecondaryContainer: "#DBE2F9",
  tertiary: "#DDBCE0", surface: "#111318", surfaceLow: "#191C20", surfaceContainer: "#1D2024", surfaceHigh: "#272A2F",
  onSurface: "#E2E2E9", onSurfaceVariant: "#C4C6D0", outline: "#8E9099", outlineVariant: "#44474F",
  error: "#FFB4AB", onError: "#690005", success: "#8ED5AC", warning: "#F5C16C",
} : {
  primary: "#435E91", onPrimary: "#FFFFFF", primaryContainer: "#D8E2FF", onPrimaryContainer: "#001A41",
  secondary: "#565F71", onSecondary: "#FFFFFF", secondaryContainer: "#DBE2F9", onSecondaryContainer: "#131C2B",
  tertiary: "#735573", surface: "#F9F9FF", surfaceLow: "#F3F3FA", surfaceContainer: "#EDEDF4", surfaceHigh: "#E7E8EE",
  onSurface: "#191C20", onSurfaceVariant: "#44474F", outline: "#74777F", outlineVariant: "#C4C6D0",
  error: "#BA1A1A", onError: "#FFFFFF", success: "#246B48", warning: "#805600",
};

export const buildTheme = (mode: PaletteMode) => {
  const c = materialColors(mode);
  return createTheme({
    palette: {
      mode, primary: { main: c.primary, contrastText: c.onPrimary }, secondary: { main: c.secondary, contrastText: c.onSecondary },
      success: { main: c.success }, warning: { main: c.warning }, error: { main: c.error, contrastText: c.onError },
      background: { default: c.surface, paper: c.surfaceLow }, text: { primary: c.onSurface, secondary: c.onSurfaceVariant }, divider: c.outlineVariant,
      action: { hover: alpha(c.onSurface, .08), selected: alpha(c.primary, .12), focus: alpha(c.onSurface, .12) },
    },
    shape: { borderRadius: 12 },
    typography: {
      fontFamily: 'Roboto, "Noto Sans SC", "Microsoft YaHei", sans-serif',
      h1: { fontSize: 57, lineHeight: "64px", fontWeight: 400, letterSpacing: -.25 },
      h2: { fontSize: 45, lineHeight: "52px", fontWeight: 400 }, h3: { fontSize: 36, lineHeight: "44px", fontWeight: 400 },
      h4: { fontSize: 32, lineHeight: "40px", fontWeight: 400 }, h5: { fontSize: 28, lineHeight: "36px", fontWeight: 400 },
      h6: { fontSize: 22, lineHeight: "28px", fontWeight: 400 },
      subtitle1: { fontSize: 16, lineHeight: "24px", fontWeight: 500, letterSpacing: .15 },
      subtitle2: { fontSize: 14, lineHeight: "20px", fontWeight: 500, letterSpacing: .1 },
      body1: { fontSize: 16, lineHeight: "24px", letterSpacing: .5 }, body2: { fontSize: 14, lineHeight: "20px", letterSpacing: .25 },
      caption: { fontSize: 12, lineHeight: "16px", letterSpacing: .4 },
      button: { fontSize: 14, lineHeight: "20px", textTransform: "none", fontWeight: 500, letterSpacing: .1 },
    },
    transitions: { easing: { easeInOut: "cubic-bezier(0.2, 0, 0, 1)" }, duration: { short: 200, standard: 300 } },
    components: {
      MuiCssBaseline: { styleOverrides: { body: { overflow: "hidden", colorScheme: mode }, "*": { scrollbarWidth: "thin", boxSizing: "border-box" }, "*:focus-visible": { outline: `3px solid ${c.primary}`, outlineOffset: 2 }, "::selection": { backgroundColor: c.primaryContainer, color: c.onPrimaryContainer } } },
      MuiPaper: { styleOverrides: { root: { backgroundImage: "none" }, outlined: { borderColor: c.outlineVariant } } },
      MuiAppBar: { styleOverrides: { root: { backgroundColor: c.surface, color: c.onSurface } } },
      MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { borderRadius: 999, minHeight: 48, padding: "10px 24px", whiteSpace: "nowrap" }, sizeSmall: { minHeight: 48, padding: "8px 16px" }, outlined: { borderColor: c.outline } } },
      MuiIconButton: { styleOverrides: { root: { width: 48, height: 48, flexShrink: 0, padding: 12 } } },
      MuiCheckbox: { styleOverrides: { root: { padding: 12 } } },
      MuiSwitch: { styleOverrides: {
        root: { width: 68, height: 48, padding: 8, flexShrink: 0 },
        sizeSmall: { width: 68, height: 48, padding: 8 },
        switchBase: { padding: 16, color: c.outline, "&.Mui-checked": { padding: 12, transform: "translateX(20px)", color: c.onPrimary, "& .MuiSwitch-thumb": { width: 24, height: 24 }, "& + .MuiSwitch-track": { backgroundColor: c.primary, opacity: 1, borderColor: "transparent" } }, "&.Mui-disabled + .MuiSwitch-track": { opacity: .38 } },
        thumb: { width: 16, height: 16, boxShadow: "none", transition: "width 150ms, height 150ms" },
        track: { borderRadius: 16, backgroundColor: c.surfaceHigh, opacity: 1, border: `2px solid ${c.outline}` },
      } },
      MuiChip: { styleOverrides: { root: { borderRadius: 8, fontWeight: 500 }, sizeSmall: { height: 28 }, outlined: { borderColor: c.outlineVariant } } },
      MuiOutlinedInput: { styleOverrides: { root: { borderRadius: 4, minHeight: 56, "&.MuiInputBase-sizeSmall": { minHeight: 48 } }, notchedOutline: { borderColor: c.outline } } },
      MuiTabs: { styleOverrides: { root: { minHeight: 48 }, indicator: { height: 3, borderRadius: "3px 3px 0 0" } } },
      MuiTab: { styleOverrides: { root: { minHeight: 48, fontWeight: 500, padding: "12px 24px", "&.Mui-selected": { color: c.primary } } } },
      MuiTableCell: { styleOverrides: { root: { borderColor: c.outlineVariant, padding: "12px 16px" }, head: { color: c.onSurfaceVariant, fontWeight: 500, backgroundColor: c.surfaceContainer }, sizeSmall: { padding: "10px 16px" } } },
      MuiTableRow: { styleOverrides: { root: { "&:last-child td": { borderBottom: 0 } } } },
      MuiDialog: { styleOverrides: { paper: { borderRadius: 28, backgroundColor: c.surfaceHigh, margin: 24 } } },
      MuiDialogTitle: { styleOverrides: { root: { fontSize: 24, fontWeight: 400, lineHeight: "32px", padding: "24px 24px 16px" } } },
      MuiDialogContent: { styleOverrides: { root: { padding: "8px 24px 16px" } } },
      MuiDialogActions: { styleOverrides: { root: { padding: "8px 24px 24px", flexWrap: "wrap", gap: 8 } } },
      MuiMenu: { styleOverrides: { paper: { backgroundColor: c.surfaceHigh, borderRadius: 4 } } },
      MuiMenuItem: { styleOverrides: { root: { minHeight: 48 } } },
      MuiListItemButton: { styleOverrides: { root: { borderRadius: 999, marginInline: 12, minHeight: 56, "&.Mui-selected": { backgroundColor: c.secondaryContainer, color: c.onSecondaryContainer, "&:hover": { backgroundColor: alpha(c.primary, .16) } } } } },
      MuiCard: { styleOverrides: { root: { borderRadius: 12, backgroundColor: c.surfaceLow } } },
      MuiCardContent: { styleOverrides: { root: { padding: 20, "&:last-child": { paddingBottom: 20 } } } },
      MuiAlert: { styleOverrides: { root: { borderRadius: 12, alignItems: "center" } } },
      MuiTooltip: { styleOverrides: { tooltip: { borderRadius: 4, fontSize: 12 } } },
      MuiLinearProgress: { styleOverrides: { root: { borderRadius: 4 } } },
    },
  });
};
