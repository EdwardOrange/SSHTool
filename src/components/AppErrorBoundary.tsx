import { Box, Button, Paper, Stack, Typography } from "@mui/material";
import React from "react";

type State = { error?: Error };

export default class AppErrorBoundary extends React.Component<React.PropsWithChildren, State> {
  state: State = {};

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("Uncaught React render error", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;

    return <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center", bgcolor: "background.default", p: 3 }}>
      <Paper variant="outlined" sx={{ width: "min(680px, 100%)", p: 3 }}>
        <Stack spacing={2}>
          <Typography variant="h5" color="error">界面加载失败</Typography>
          <Typography color="text.secondary">程序仍在运行。请复制下面的信息用于诊断，或重新加载界面。</Typography>
          <Box component="pre" className="mono" sx={{ m: 0, p: 2, borderRadius: 1, overflow: "auto", whiteSpace: "pre-wrap", bgcolor: "action.hover", color: "text.primary" }}>
            {this.state.error.stack || this.state.error.message}
          </Box>
          <Button variant="contained" onClick={() => window.location.reload()}>重新加载</Button>
        </Stack>
      </Paper>
    </Box>;
  }
}
