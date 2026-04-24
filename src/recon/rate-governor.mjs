/**
 * Per-host adaptive rate governor.
 *
 * Responsibilities:
 *   1. Enforce a minimum delay between consecutive requests to the same host
 *      (`minInterval = 1000 / currentRps`).
 *   2. On `429 Too Many Requests`, back off exponentially:
 *        - read `Retry-After` (seconds or HTTP-date) if provided
 *        - otherwise double the host's cooldown, clamped to `maxBackoffMs`
 *        - halve the host's effective RPS (down to `minRps`) so we don't
 *          immediately retry at the same rate.
 *   3. On a streak of healthy 2xx/3xx responses, gently raise RPS back
 *      toward `maxRps` (additive increase).
 *
 * The governor is transport-agnostic — callers use {@link acquire} to wait
 * their turn and {@link report} to feed a completed request's status back.
 */

function now() {
  return Date.now();
}

function parseRetryAfter(header) {
  if (!header) return 0;
  const s = String(header).trim();
  if (/^\d+$/.test(s)) return Number(s) * 1000;
  const asDate = Date.parse(s);
  if (!Number.isNaN(asDate)) return Math.max(0, asDate - now());
  return 0;
}

function hostOf(url) {
  try {
    return new URL(String(url)).hostname;
  } catch {
    return 'unknown';
  }
}

export class RateGovernor {
  /**
   * @param {object} [opts]
   * @param {number} [opts.maxRps]        target steady-state RPS per host (default 5)
   * @param {number} [opts.minRps]        floor for adaptive throttling (default 0.5)
   * @param {number} [opts.maxBackoffMs]  max cooldown after 429 (default 60_000)
   * @param {number} [opts.increaseEvery] healthy requests between RPS bumps (default 10)
   * @param {number} [opts.increaseBy]    RPS increment per bump (default 0.5)
   */
  constructor({ maxRps = 5, minRps = 0.5, maxBackoffMs = 60_000, increaseEvery = 10, increaseBy = 0.5 } = {}) {
    this.maxRps = maxRps;
    this.minRps = minRps;
    this.maxBackoffMs = maxBackoffMs;
    this.increaseEvery = increaseEvery;
    this.increaseBy = increaseBy;

    /** @type {Map<string, { rps: number, nextAllowed: number, consecutiveOk: number, consecutive429: number }>} */
    this.hosts = new Map();
  }

  state(url) {
    const h = hostOf(url);
    let s = this.hosts.get(h);
    if (!s) {
      s = {
        rps: this.maxRps,
        nextAllowed: 0,
        consecutiveOk: 0,
        consecutive429: 0,
      };
      this.hosts.set(h, s);
    }
    return { h, s };
  }

  /**
   * Block until it's safe to issue a request to the target host. Must be
   * paired with {@link report} after the response arrives.
   *
   * @param {string} url
   */
  async acquire(url) {
    const { s } = this.state(url);
    const wait = s.nextAllowed - now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    const interval = 1000 / Math.max(this.minRps, s.rps);
    s.nextAllowed = now() + interval;
  }

  /**
   * @param {string} url
   * @param {{ status?: number, retryAfter?: string | number | null } | null} res
   */
  report(url, res) {
    const { s } = this.state(url);
    const status = Number(res?.status || 0);
    if (status === 429) {
      s.consecutive429 += 1;
      s.consecutiveOk = 0;
      const retryMs = parseRetryAfter(res?.retryAfter);
      const fallback = Math.min(
        this.maxBackoffMs,
        1000 * Math.pow(2, Math.min(s.consecutive429, 6)),
      );
      const cooldown = Math.max(retryMs, fallback);
      s.nextAllowed = Math.max(s.nextAllowed, now() + cooldown);
      s.rps = Math.max(this.minRps, s.rps / 2);
      return { backedOffMs: cooldown, newRps: s.rps };
    }

    if (status >= 500 && status < 600) {
      s.consecutiveOk = 0;
      return { backedOffMs: 0, newRps: s.rps };
    }

    if (status >= 200 && status < 400) {
      s.consecutive429 = 0;
      s.consecutiveOk += 1;
      if (s.consecutiveOk >= this.increaseEvery && s.rps < this.maxRps) {
        s.rps = Math.min(this.maxRps, s.rps + this.increaseBy);
        s.consecutiveOk = 0;
      }
    }
    return { backedOffMs: 0, newRps: s.rps };
  }

  snapshot() {
    const out = {};
    for (const [h, s] of this.hosts.entries()) {
      out[h] = {
        rps: Number(s.rps.toFixed(2)),
        consecutive429: s.consecutive429,
        consecutiveOk: s.consecutiveOk,
      };
    }
    return out;
  }
}
