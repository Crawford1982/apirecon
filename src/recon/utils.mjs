/** @param {number} ms */
export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Embed arbitrary text inside a bash single-quoted segment (legacy helper). */
export function sanitizeForShell(str) {
  return String(str).replace(/'/g, `'\\''`);
}
