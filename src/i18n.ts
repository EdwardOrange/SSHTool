import i18n from "i18next";
import { initReactI18next } from "react-i18next";

const resources = {
  zh: { translation: {
    appName: "SSH 运维终端", servers: "服务器", overview: "总览", terminal: "终端", monitor: "资源监控",
    firewall: "防火墙", sftp: "文件传输", forwarding: "端口转发", addServer: "添加服务器", commandLog: "命令记录台",
    searchServers: "搜索服务器", connect: "连接", disconnect: "断开", connected: "已连接", disconnected: "未连接",
    cpu: "CPU", memory: "内存", disk: "磁盘", network: "网络", connections: "活动连接", topProcesses: "高占用进程",
    inbound: "入站", outbound: "出站", rules: "规则", addRule: "添加规则", apply: "生成变更计划", status: "状态",
    host: "主机", username: "用户名", port: "端口", group: "分组", auth: "认证方式", save: "保存", cancel: "取消",
    settings: "设置", language: "语言", theme: "主题", noHost: "选择一台服务器开始", allCommands: "全部来源",
    clear: "清空视图", export: "导出", copy: "复制", filter: "筛选命令", live: "实时", history: "历史趋势",
  } },
  en: { translation: {
    appName: "SSH Operations Terminal", servers: "Servers", overview: "Overview", terminal: "Terminal", monitor: "Monitoring",
    firewall: "Firewall", sftp: "File Transfer", forwarding: "Port Forwarding", addServer: "Add server", commandLog: "Command Ledger",
    searchServers: "Search servers", connect: "Connect", disconnect: "Disconnect", connected: "Connected", disconnected: "Disconnected",
    cpu: "CPU", memory: "Memory", disk: "Disk", network: "Network", connections: "Connections", topProcesses: "Top processes",
    inbound: "Inbound", outbound: "Outbound", rules: "Rules", addRule: "Add rule", apply: "Create change plan", status: "Status",
    host: "Host", username: "Username", port: "Port", group: "Group", auth: "Authentication", save: "Save", cancel: "Cancel",
    settings: "Settings", language: "Language", theme: "Theme", noHost: "Select a server to begin", allCommands: "All sources",
    clear: "Clear view", export: "Export", copy: "Copy", filter: "Filter commands", live: "Live", history: "History",
  } },
};

i18n.use(initReactI18next).init({ resources, lng: localStorage.getItem("locale") || "zh", fallbackLng: "zh", interpolation: { escapeValue: false } });
export default i18n;
