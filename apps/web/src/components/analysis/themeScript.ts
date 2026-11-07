/**
 * The theme the analysis page starts in, applied before the first paint.
 *
 * `useUiTheme` sets `data-ui-theme` after hydration, which on a light-mode
 * machine painted one dark frame first. The root layout, a server component,
 * prints this script in its <head> (a script tag inside a client component is
 * refused by React) so the attribute is on <html> before the page paints.
 * `next/script` does not serve: its inline scripts run from the bootstrap
 * chunk, after first paint. The script does nothing outside
 * `/analysis/`, so every other page keeps its own look. It is inline, which
 * the console's CSP allows (`script-src 'self' 'unsafe-inline'`,
 * lib/securityHeaders.ts), holds no data from the request, and fails quiet: a
 * browser that refuses storage falls back to the OS setting, and any error
 * leaves the dark default.
 *
 * Kept out of the client module so a server layout can import the string.
 */

import { PREVIOUS_NAME_FORMAT_PREFIX } from "@/lib/previousName";

export const THEME_STORAGE_KEY = "malspark.ui-theme";

/** The key a release before the product's rename (T-576) remembered the choice
 *  under (`<previous>.ui-theme`): read when the current key holds nothing, so a
 *  reader's choice survives the upgrade. Never written. */
export const PREVIOUS_THEME_STORAGE_KEY = `${PREVIOUS_NAME_FORMAT_PREFIX.replace(/-$/, ".")}ui-theme`;

// The keys are constants, so the script is still one constant string; a test
// pins it to THEME_STORAGE_KEY and PREVIOUS_THEME_STORAGE_KEY.
export const THEME_BOOT_SCRIPT = `(function(){try{if(!/^\\/analysis\\//.test(location.pathname))return;var t=null;try{t=localStorage.getItem(${JSON.stringify(THEME_STORAGE_KEY)});if(t===null)t=localStorage.getItem(${JSON.stringify(PREVIOUS_THEME_STORAGE_KEY)})}catch(e){}if(t!=="light"&&t!=="dark"){t=window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}document.documentElement.setAttribute("data-ui-theme",t)}catch(e){}})();`;
