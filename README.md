# SSH 运维终端

Windows 优先、无代理的 SSH 桌面运维客户端。界面使用 Material Design，提供多服务器终端、资源监控、防火墙安全变更、SFTP、端口转发与完整命令记录。

## 开发

```powershell
npm install
npm run desktop:dev
```

仅运行浏览器界面（自动使用演示数据）：

```powershell
npm run dev
```

## 构建

```powershell
npm run test
npm run build
npm run desktop:build
```

Tauri 构建产物位于 `src-tauri/target/release/bundle`。便携版为 `src-tauri/target/release/ssh-operations-terminal.exe`。
