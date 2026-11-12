/**
 * Robust cross-browser clipboard copy utility.
 * Supports modern Clipboard API in secure contexts (HTTPS / localhost),
 * and transparently falls back to document.execCommand('copy') on insecure LAN HTTP
 * origins (e.g. http://192.168.x.x:5173), older browsers, and restricted webviews.
 *
 * @param {string} text - The text content to copy to clipboard
 * @returns {Promise<boolean>} - True if copied successfully, false otherwise
 */
export async function copyToClipboard(text) {
  const content = typeof text === 'string' ? text : String(text ?? '');

  if (!content) {
    return false;
  }

  // 1. Try modern async Clipboard API if available and document is in a secure context
  if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    try {
      await navigator.clipboard.writeText(content);
      return true;
    } catch {
      // If writeText throws (e.g. NotAllowedError, insecure context, unfocused document), fallback below
    }
  }

  // 2. Universal fallback: create a hidden, selectable textarea and execute 'copy'
  try {
    if (typeof document === 'undefined') {
      return false;
    }

    const textArea = document.createElement('textarea');
    textArea.value = content;

    // Position far off-screen and prevent page jump/scroll
    textArea.style.position = 'fixed';
    textArea.style.top = '-9999px';
    textArea.style.left = '-9999px';
    textArea.style.width = '2em';
    textArea.style.height = '2em';
    textArea.style.padding = '0';
    textArea.style.border = 'none';
    textArea.style.outline = 'none';
    textArea.style.boxShadow = 'none';
    textArea.style.background = 'transparent';
    textArea.setAttribute('readonly', '');

    document.body.appendChild(textArea);

    // iOS and Safari selection compatibility
    textArea.focus({ preventScroll: true });
    textArea.select();
    textArea.setSelectionRange(0, content.length);

    const successful = document.execCommand('copy');
    document.body.removeChild(textArea);

    return Boolean(successful);
  } catch (err) {
    console.error('Universal clipboard copy failed:', err);
    return false;
  }
}

