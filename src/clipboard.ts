/** Report success only when the clipboard API or the WebView fallback succeeds. */
export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch { /* Some WebViews only support the legacy clipboard command. */ }
  const previousFocus = document.activeElement;
  const input = document.createElement("textarea");
  input.value = text;
  input.style.cssText = "position:fixed;left:-10000px;top:0";
  document.body.appendChild(input);
  try {
    input.focus();
    input.select();
    if (!document.execCommand("copy")) throw new Error("复制失败，请检查系统剪贴板权限后重试");
  } catch {
    throw new Error("复制失败，请检查系统剪贴板权限后重试");
  } finally {
    input.remove();
    if (previousFocus instanceof HTMLElement) previousFocus.focus();
  }
}
