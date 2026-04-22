export class TrafficFilter {
  /**
   * @param {unknown[]} traffic
   */
  static jsonApis(traffic) {
    return traffic.filter((req) => {
      if (!req || typeof req !== 'object') return false;
      const r = /** @type {Record<string, unknown>} */ (req);
      if (r.type !== 'request') return false;
      if (typeof r.status !== 'number') return false;

      const rt = String(r.resourceType || '').toLowerCase();
      const isApi = ['xhr', 'fetch', 'document'].includes(rt);

      const rh = /** @type {Record<string, string>} */ (r.responseHeaders || {});
      const ct = (rh['content-type'] || rh['Content-Type'] || '').toLowerCase();
      const isJson = ct.includes('application/json');

      const url = String(r.url || '');
      const trackerPatterns = [
        /google-analytics/,
        /analytics/,
        /segment\.(com|io)/,
        /mixpanel/,
        /sentry/,
        /datadog/,
        /newrelic/,
        /bugsnag/,
        /amplitude/,
        /hotjar/,
        /clarity\.ms/,
        /facebook\.net/,
        /doubleclick/,
        /\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ttf|eot|ico)(\?|$)/i,
      ];
      const isNotTracker = !trackerPatterns.some((p) => p.test(url));

      return isApi && isJson && isNotTracker;
    });
  }
}
