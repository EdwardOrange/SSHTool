import { describe, expect, it } from "vitest";
import { getContrastRatio } from "@mui/material/styles";
import { materialColors } from "./theme";

describe("Material color roles", () => {
  for (const mode of ["light", "dark"] as const) {
    it(mode + " keeps body and action text at WCAG AA contrast", () => {
      const c = materialColors(mode);
      for (const [foreground, background] of [
        [c.onSurface, c.surface], [c.onSurfaceVariant, c.surfaceLow],
        [c.onPrimary, c.primary], [c.onPrimaryContainer, c.primaryContainer],
        [c.onSecondaryContainer, c.secondaryContainer], [c.error, c.surface],
        [c.success, c.surface], [c.warning, c.surface],
      ]) expect(getContrastRatio(foreground, background)).toBeGreaterThanOrEqual(4.5);
    });
  }
});
