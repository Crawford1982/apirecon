import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Default Google Chrome "User Data" directory for this OS (Playwright persistent context path).
 */
export function defaultChromeUserDataDir() {
  const h = homedir();
  if (process.platform === 'darwin') {
    return join(h, 'Library', 'Application Support', 'Google', 'Chrome');
  }
  if (process.platform === 'win32') {
    return join(h, 'AppData', 'Local', 'Google', 'Chrome', 'User Data');
  }
  return join(h, '.config', 'google-chrome');
}
