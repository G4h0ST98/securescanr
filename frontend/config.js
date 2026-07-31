/* SecureScanr — shared runtime config.
 *
 * One definition of the API origin for the whole site. This used to be a
 * `const API_BASE` repeated in 14 pages (plus one URL inlined straight into a
 * fetch in generators.html), so repointing the API meant editing 15 files and
 * missing some.
 *
 * Loaded before every page's inline script, so pages just use API_BASE.
 * Served from the site root: <script src="/config.js"></script>
 */
(function () {
  var host = location.hostname;

  /* '' covers file:// — opening a page straight off disk still talks to a
     local Flask rather than silently reaching for production. */
  var isLocal = host === 'localhost' || host === '127.0.0.1' ||
                host === '[::1]' || host === '::1' || host === '';

  /* Escape hatch for testing against another backend without editing files:
       localStorage.setItem('ss_api_base', 'http://192.168.1.20:5000')
     Ignored unless it is a well-formed http(s) origin. */
  var override = null;
  try { override = localStorage.getItem('ss_api_base'); } catch (e) { /* private mode */ }
  if (override && /^https?:\/\/[^\s]+$/.test(override)) {
    window.API_BASE = override.replace(/\/+$/, '');
    return;
  }

  window.API_BASE = isLocal ? 'http://localhost:5000' : 'https://api.securescanr.com';
})();
