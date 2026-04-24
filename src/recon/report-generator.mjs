/**
 * Turn a {@link CrossAccountReplay.summarize} result into human-readable
 * bounty reports (Markdown + interactive HTML).
 *
 * Markdown: optimised for direct paste into HackerOne / Bugcrowd / Intigriti.
 * HTML:     self-contained interactive report with severity badges, field-level
 *           diff tables, copy-to-clipboard curl commands, and collapsible sections.
 */

/**
 * @typedef {ReturnType<import('./cross-account-replay.mjs').CrossAccountReplay['summarize']>} CrossAccountSummary
 */

/**
 * @param {any} r  one result entry
 */
function getSeverityFromResult(r) {
  // Prefer field-level severity from evidence chain (deriveSeverity), fall back to leak score.
  if (r.severity?.label) return r.severity;
  const verdictKind = r.verdict?.kind;
  const leakScore = r.analyses?.swap?.leakScore ?? 0;
  if (verdictKind !== 'confirmed' && verdictKind !== 'likely') return { label: 'Informational', cvss: 0, color: '#6b7280' };
  if (leakScore >= 60) return { label: 'Critical', cvss: 9.1, color: '#dc2626' };
  if (leakScore >= 30) return { label: 'High', cvss: 7.6, color: '#ea580c' };
  if (leakScore >= 10) return { label: 'Medium', cvss: 5.5, color: '#ca8a04' };
  return { label: 'Low', cvss: 3.5, color: '#2563eb' };
}

/**
 * @param {any} verdictKind
 * @param {number} leakScore
 */
function toSeverity(verdictKind, leakScore) {
  if (verdictKind !== 'confirmed' && verdictKind !== 'likely') return { label: 'Informational', score: 0 };
  if (leakScore >= 60) return { label: 'Critical', score: 9.0 };
  if (leakScore >= 30) return { label: 'High', score: 7.5 };
  if (leakScore >= 10) return { label: 'Medium', score: 5.5 };
  return { label: 'Low', score: 3.5 };
}

/** @param {any} finding */
function findingTitle(finding) {
  if (finding.idorSource === 'graphql-variable') {
    const opName = finding.pathTemplate?.split('·')[1]?.trim() || '(gql op)';
    return `IDOR via GraphQL variable swap — ${opName}`;
  }
  const template = finding.pathTemplate || finding.path || 'endpoint';
  return `IDOR via ${finding.idorSource} swap — ${finding.method} ${template}`;
}

/** @param {Record<string, any>} signals */
function signalSummary(signals) {
  const rows = Object.entries(signals || {})
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 8)
    .map(([kind, info]) => `- **${kind}** ×${info.count} — e.g. \`${(info.samples?.[0] || '').toString().slice(0, 60)}\``);
  return rows.length ? rows.join('\n') : '_(no PII signals detected)_';
}

/** @param {any} probe */
function requestBlock(probe) {
  if (!probe || !probe.url) return '';
  const method = probe.label?.split('/')[1]?.includes('own') ? 'GET' : undefined; // informational only
  void method;
  const lines = [`${probe.url}`];
  if (probe.body) lines.push('```json', JSON.stringify(probe.body, null, 2), '```');
  return lines.join('\n');
}

/** @param {any} probe */
function responseBlock(probe) {
  if (!probe) return '_(no response)_';
  if (probe.error) return `_error: ${probe.error}_`;
  const status = `HTTP ${probe.status} ${probe.statusText || ''}`.trim();
  const sample =
    probe.body ? JSON.stringify(probe.body, null, 2) :
    probe.bodyText ? probe.bodyText :
    '(empty)';
  const truncated = sample.length > 1200 ? sample.slice(0, 1200) + '\n// …truncated…' : sample;
  return ['```', status, truncated, '```'].join('\n');
}

/** @param {import('./evidence-chain.mjs').FieldDiff[]} fields */
function fieldDiffTable(fields) {
  if (!fields || fields.length === 0) return '_No field-level changes detected._';
  const rows = fields.slice(0, 20).map(
    (f) => `| \`${f.path}\` | \`${f.ownValue.slice(0, 40)}\` | \`${f.swapValue.slice(0, 40)}\` | **${f.sensitivityLabel}** |`,
  );
  return [
    '| JSON path | Baseline (own) | Swap (foreign) | Sensitivity |',
    '|-----------|---------------|----------------|-------------|',
    ...rows,
  ].join('\n');
}

/** @param {any} r  one entry of summary.all */
function reportFor(r) {
  const swapLeak = r.analyses?.swap?.leakScore ?? 0;
  const sev = r.severity?.label ? { label: r.severity.label, score: r.severity.cvss ?? 0 } : toSeverity(r.verdict.kind, swapLeak);
  const title = findingTitle(r.finding);

  const identityLines = r.analyses?.swap?.identityHintHits?.length
    ? `**Swap response contains target identity hint(s):** ${r.analyses.swap.identityHintHits.join(', ')}`
    : '_No explicit target identity hit — verdict driven by response shape parity._';

  return [
    `## ${title}`,
    '',
    `**Severity:** ${sev.label} (${sev.score.toFixed(1)}) · **Verdict:** \`${r.verdict.kind}\` — ${r.verdict.reason}`,
    '',
    `**Endpoint template:** \`${r.finding.pathTemplate || r.finding.path}\``,
    `**Method:** ${r.finding.method}`,
    `**ID kind:** ${r.finding.idType}  (own=\`${r.ownId}\` · swap=\`${r.swapId}\`)`,
    '',
    '### Impact',
    '',
    sev.label === 'Informational'
      ? 'Cross-account request completed; response either blocked or identical to the baseline.'
      : `Authenticated as account A, apirecon replayed the captured endpoint with the scope identifier ` +
        `for another tenant and received a shape-compatible response with a PII/signal load of \`${swapLeak}\`. ` +
        `This indicates the endpoint does not enforce tenant boundary on the ${r.finding.idorSource} ` +
        `identifier.`,
    '',
    '### Reproduction',
    '',
    '**1. Baseline (authorised — request your own record):**',
    '',
    '```',
    r.curl?.own || '(no baseline curl)',
    '```',
    '',
    '**Baseline response (truncated):**',
    responseBlock(r.probes?.own),
    '',
    '**2. Cross-tenant probe (same auth, target scope id):**',
    '',
    '```',
    r.curl?.swap || '(no swap curl)',
    '```',
    '',
    '**Cross-tenant response (truncated):**',
    responseBlock(r.probes?.swap),
    '',
    '### Evidence',
    '',
    identityLines,
    r.evidenceChain?.summary ? `\n**Field-level analysis:** ${r.evidenceChain.summary}` : '',
    '',
    '**Field-level diff (changed values between baseline and cross-tenant response):**',
    '',
    fieldDiffTable(r.evidenceChain?.changedFields),
    '',
    '**Signal scan — all PII/identity markers in cross-tenant response:**',
    '',
    signalSummary(r.analyses?.swap?.signals),
    '',
    '**Body diff metrics:**',
    r.diff
      ? [
          `- shape similarity (jaccard): \`${r.diff.jaccard}\``,
          `- shared JSON paths: ${r.diff.sharedPaths}/${r.diff.totalPaths}`,
          `- size ratio (swap/baseline): \`${r.diff.sizeRatio}\``,
          `- leakScore Δ: \`${r.diff.leakScoreDelta}\``,
          `- field-level evidence score: \`${r.evidenceChain?.evidenceScore ?? 'n/a'}\``,
        ].join('\n')
      : '_no diff computed_',
    '',
    '### Risk-scoring rationale',
    '',
    (r.finding.riskReasons || []).map((x) => `- ${x}`).join('\n') || '_no reasons recorded_',
    '',
    '---',
    '',
  ].join('\n');
}

/**
 * Render the full bounty report.
 *
 * @param {CrossAccountSummary} summary
 * @param {object} [opts]
 * @param {string} [opts.target]   target origin (for the title)
 * @param {string} [opts.toolVersion]
 */
export function renderBountyReport(summary, opts = {}) {
  const target = opts.target || 'target';
  const version = opts.toolVersion || 'apirecon';
  const top = [...(summary.confirmed || []), ...(summary.likely || [])].sort((a, b) => {
    const la = a.analyses?.swap?.leakScore ?? 0;
    const lb = b.analyses?.swap?.leakScore ?? 0;
    return lb - la;
  });

  const header = [
    `# IDOR findings — ${target}`,
    '',
    `_Generated by ${version} on ${new Date().toISOString()}_`,
    '',
    '## Executive summary',
    '',
    `- **Confirmed cross-tenant reads:** ${summary.stats.confirmed || 0}`,
    `- **Likely cross-tenant reads:**   ${summary.stats.likely || 0}`,
    `- **Properly blocked (401/403/404):** ${summary.stats.blocked || 0}`,
    `- **Identical-to-baseline (public data):** ${summary.stats.public || 0}`,
    `- **Inconclusive:** ${summary.stats.inconclusive || 0}`,
    '',
    top.length
      ? `The top ${top.length} reportable finding(s) are detailed below, sorted by the PII signal volume observed in the cross-tenant response.`
      : '_No confirmed or likely cross-tenant reads were observed in this run. No report body generated._',
    '',
    '---',
    '',
  ].join('\n');

  const body = top.map(reportFor).join('\n');
  return header + body;
}

// ─── HTML report ──────────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  Critical: { bg: '#fee2e2', border: '#dc2626', badge: '#dc2626', text: '#7f1d1d' },
  High:     { bg: '#ffedd5', border: '#ea580c', badge: '#ea580c', text: '#7c2d12' },
  Medium:   { bg: '#fefce8', border: '#ca8a04', badge: '#ca8a04', text: '#713f12' },
  Low:      { bg: '#eff6ff', border: '#2563eb', badge: '#2563eb', text: '#1e3a5f' },
  Informational: { bg: '#f3f4f6', border: '#6b7280', badge: '#6b7280', text: '#374151' },
};

const VERDICT_COLORS = {
  confirmed: '#dc2626',
  likely: '#ca8a04',
  blocked: '#16a34a',
  public: '#6b7280',
  inconclusive: '#9ca3af',
};

/** @param {string} s */
function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** @param {any} r */
function htmlFinding(r, idx) {
  const sev = getSeverityFromResult(r);
  const sevColors = SEVERITY_COLORS[sev.label] || SEVERITY_COLORS.Informational;
  const verdictColor = VERDICT_COLORS[r.verdict?.kind] || '#9ca3af';
  const title = esc(findingTitle(r.finding));
  const swapUrl = esc(r.probes?.swap?.url || r.finding?.path || '');
  const ownCurl = esc(r.curl?.own || '');
  const swapCurl = esc(r.curl?.swap || '');
  const ownStatus = r.probes?.own?.status ?? '?';
  const swapStatus = r.probes?.swap?.status ?? '?';
  const ownBody = esc(
    r.probes?.own?.body ? JSON.stringify(r.probes.own.body, null, 2).slice(0, 2000) : r.probes?.own?.bodyText?.slice(0, 2000) || '(empty)',
  );
  const swapBody = esc(
    r.probes?.swap?.body ? JSON.stringify(r.probes.swap.body, null, 2).slice(0, 2000) : r.probes?.swap?.bodyText?.slice(0, 2000) || '(empty)',
  );
  const jaccard = r.diff?.jaccard ?? 'n/a';
  const evidenceScore = r.evidenceChain?.evidenceScore ?? 0;
  const leakScore = r.analyses?.swap?.leakScore ?? 0;

  // Field-level diff table rows.
  const fieldRows = (r.evidenceChain?.changedFields || []).slice(0, 25).map((f) => {
    const sensColors = { critical: '#fee2e2', high: '#ffedd5', medium: '#fefce8', low: '#eff6ff', '': '#f9fafb' };
    const bg = sensColors[f.sensitivityLabel] || '#f9fafb';
    return `<tr style="background:${bg}">
      <td><code>${esc(f.path)}</code></td>
      <td class="mono">${esc(f.ownValue.slice(0, 80))}</td>
      <td class="mono leak">${esc(f.swapValue.slice(0, 80))}</td>
      <td><span class="badge" style="background:${sevColors.badge};color:#fff">${esc(f.sensitivityLabel)}</span></td>
    </tr>`;
  }).join('');

  // PII signals.
  const signalRows = Object.entries(r.analyses?.swap?.signals || {})
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 8)
    .map(([kind, info]) =>
      `<tr><td>${esc(kind)}</td><td>${info.count}</td><td class="mono">${esc((info.samples?.[0] || '').toString().slice(0, 60))}</td></tr>`,
    ).join('');

  return `
<div class="finding" id="f${idx}" style="border-left:4px solid ${sevColors.border};background:${sevColors.bg}">
  <div class="finding-header" onclick="toggle('fd${idx}')">
    <div class="finding-title-row">
      <span class="severity-badge" style="background:${sevColors.badge}">${esc(sev.label)} ${sev.cvss ? sev.cvss.toFixed(1) : ''}</span>
      <span class="verdict-badge" style="background:${verdictColor}">${esc(r.verdict?.kind || '')}</span>
      <span class="finding-title">${title}</span>
    </div>
    <div class="finding-meta">
      <span>${esc(r.finding?.method || 'GET')}</span>
      <code>${esc(r.finding?.pathTemplate || r.finding?.path || '')}</code>
      <span>·</span>
      <span>own=<code>${esc(r.ownId?.slice(0, 16) || '')}…</code></span>
      <span>swap=<code>${esc(r.swapId?.slice(0, 16) || '')}…</code></span>
      <span>·</span>
      <span>evidence=${evidenceScore}</span>
      <span>·</span>
      <span>shape=${jaccard}</span>
    </div>
  </div>
  <div class="finding-body" id="fd${idx}">

    <div class="section-label">Impact</div>
    <p>${esc(r.evidenceChain?.summary || r.verdict?.reason || '')}</p>
    ${r.evidenceChain?.keyLeaks?.length
      ? `<p><strong>Fields leaking foreign data:</strong> ${r.evidenceChain.keyLeaks.map((l) => `<code>${esc(l)}</code>`).join('  ')}</p>`
      : ''}

    <div class="two-col">
      <div>
        <div class="section-label">Baseline (own id) — HTTP ${ownStatus}</div>
        <div class="curl-block">
          <button class="copy-btn" onclick="copyText(this, 'curl${idx}-own')">Copy</button>
          <pre id="curl${idx}-own">${ownCurl}</pre>
        </div>
        <pre class="response-block">${ownBody}</pre>
      </div>
      <div>
        <div class="section-label">Cross-tenant probe (foreign id) — HTTP ${swapStatus}</div>
        <div class="curl-block">
          <button class="copy-btn" onclick="copyText(this, 'curl${idx}-swap')">Copy</button>
          <pre id="curl${idx}-swap">${swapCurl}</pre>
        </div>
        <pre class="response-block leak-response">${swapBody}</pre>
      </div>
    </div>

    ${fieldRows ? `
    <div class="section-label">Field-level diff — changed values between accounts</div>
    <table class="field-table">
      <thead><tr><th>JSON path</th><th>Baseline value</th><th>Foreign value ⚠</th><th>Sensitivity</th></tr></thead>
      <tbody>${fieldRows}</tbody>
    </table>` : ''}

    ${signalRows ? `
    <div class="section-label">PII / identity signals in cross-tenant response</div>
    <table class="field-table">
      <thead><tr><th>Signal type</th><th>Count</th><th>Sample</th></tr></thead>
      <tbody>${signalRows}</tbody>
    </table>` : ''}

    <div class="metrics-row">
      <span>Shape jaccard: <strong>${jaccard}</strong></span>
      <span>Leak score: <strong>${leakScore}</strong></span>
      <span>Evidence: <strong>${evidenceScore}</strong></span>
      <span>Size ratio: <strong>${r.diff?.sizeRatio ?? 'n/a'}</strong></span>
      <span>CVSS: <strong>${sev.cvss ? sev.cvss.toFixed(1) : 'n/a'}</strong></span>
    </div>

    <details>
      <summary>Risk scoring rationale</summary>
      <ul>${(r.finding?.riskReasons || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
    </details>
  </div>
</div>`;
}

/**
 * Render a self-contained interactive HTML bounty report.
 *
 * @param {CrossAccountSummary} summary
 * @param {object} [opts]
 * @param {string} [opts.target]
 * @param {string} [opts.toolVersion]
 */
export function renderHtmlReport(summary, opts = {}) {
  const target = esc(opts.target || 'target');
  const toolVersion = esc(opts.toolVersion || 'apirecon');
  const generatedAt = new Date().toISOString();
  const s = summary.stats;

  const reportable = [...(summary.confirmed || []), ...(summary.likely || [])];

  const findingsHtml = reportable.length
    ? reportable.map(htmlFinding).join('\n')
    : `<div class="no-findings">
        <p>No confirmed or likely cross-tenant reads were found in this run.</p>
        <p>Endpoints tested: ${(summary.all || []).length}</p>
      </div>`;

  const topSev = reportable.length ? (getSeverityFromResult(reportable[0])?.label || 'None') : 'None';
  const topCvss = reportable.length ? (getSeverityFromResult(reportable[0])?.cvss || 0).toFixed(1) : 'n/a';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>apirecon — IDOR Report: ${target}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  a { color: #60a5fa; }

  /* Header */
  .report-header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid #334155; padding: 2rem 2.5rem; }
  .report-header h1 { font-size: 1.5rem; font-weight: 700; color: #f1f5f9; margin-bottom: 0.25rem; }
  .report-header .subtitle { color: #94a3b8; font-size: 0.875rem; }
  .report-header .tool-badge { display: inline-block; background: #1d4ed8; color: #bfdbfe;
    padding: 0.15rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; margin-right: 0.5rem; }

  /* Stats bar */
  .stats-bar { display: flex; gap: 1rem; flex-wrap: wrap;
    background: #1e293b; border-bottom: 1px solid #334155; padding: 1rem 2.5rem; }
  .stat-card { background: #0f172a; border-radius: 0.5rem; padding: 0.75rem 1.25rem;
    border: 1px solid #334155; min-width: 130px; }
  .stat-card .stat-value { font-size: 2rem; font-weight: 700; line-height: 1; }
  .stat-card .stat-label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-confirmed { border-color: #dc2626; }
  .stat-confirmed .stat-value { color: #f87171; }
  .stat-likely { border-color: #ca8a04; }
  .stat-likely .stat-value { color: #fbbf24; }
  .stat-blocked { border-color: #16a34a; }
  .stat-blocked .stat-value { color: #4ade80; }
  .stat-severity { border-color: #2563eb; }
  .stat-severity .stat-value { color: #60a5fa; font-size: 1.25rem; }

  /* Main layout */
  .main { max-width: 1400px; margin: 0 auto; padding: 2rem 2.5rem; }

  /* Finding cards */
  .finding { border-radius: 0.75rem; margin-bottom: 1.5rem; overflow: hidden;
    border: 1px solid #334155; }
  .finding-header { padding: 1rem 1.25rem; cursor: pointer; background: rgba(255,255,255,0.03); }
  .finding-header:hover { background: rgba(255,255,255,0.06); }
  .finding-title-row { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.4rem; }
  .finding-title { font-weight: 600; font-size: 0.95rem; color: #f1f5f9; }
  .finding-meta { font-size: 0.8rem; color: #94a3b8; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
  .finding-meta code { background: rgba(255,255,255,0.07); padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.78rem; }
  .finding-body { padding: 1.25rem; border-top: 1px solid #334155; display: none; }
  .finding-body.open { display: block; }

  /* Badges */
  .severity-badge, .verdict-badge, .badge {
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px;
    font-size: 0.72rem; font-weight: 700; color: #fff; letter-spacing: 0.03em; }

  /* Sections */
  .section-label { font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.1em; color: #64748b; margin: 1rem 0 0.5rem; }
  p { margin-bottom: 0.75rem; font-size: 0.9rem; }
  code { background: rgba(255,255,255,0.08); padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.85em; }

  /* Two-column layout for request/response */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 1rem 0; }
  @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }

  /* Curl blocks */
  .curl-block { position: relative; margin-bottom: 0.5rem; }
  .curl-block pre { background: #020617; border: 1px solid #1e3a5f; border-radius: 0.5rem;
    padding: 0.75rem 3rem 0.75rem 0.75rem; font-size: 0.75rem; white-space: pre-wrap;
    word-break: break-all; color: #93c5fd; max-height: 8rem; overflow-y: auto; }
  .copy-btn { position: absolute; top: 0.4rem; right: 0.4rem; background: #1d4ed8;
    color: #fff; border: none; border-radius: 0.35rem; padding: 0.2rem 0.5rem;
    font-size: 0.7rem; cursor: pointer; z-index: 1; }
  .copy-btn:hover { background: #2563eb; }
  .copy-btn.copied { background: #16a34a; }

  /* Response blocks */
  .response-block { background: #020617; border: 1px solid #1e293b; border-radius: 0.5rem;
    padding: 0.75rem; font-size: 0.72rem; white-space: pre-wrap; word-break: break-all;
    max-height: 14rem; overflow-y: auto; color: #94a3b8; }
  .leak-response { border-color: #7f1d1d; color: #fca5a5; }

  /* Field diff table */
  .field-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin: 0.5rem 0 1rem; }
  .field-table th { background: #1e293b; text-align: left; padding: 0.4rem 0.6rem;
    font-weight: 600; color: #94a3b8; font-size: 0.72rem; text-transform: uppercase; }
  .field-table td { padding: 0.35rem 0.6rem; border-bottom: 1px solid #1e293b; vertical-align: top; }
  .field-table td.mono { font-family: monospace; font-size: 0.78rem; }
  .field-table td.leak { color: #f87171; }
  .field-table tr:hover td { background: rgba(255,255,255,0.03); }

  /* Metrics row */
  .metrics-row { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem;
    color: #94a3b8; margin: 1rem 0 0.5rem; background: #1e293b;
    border-radius: 0.4rem; padding: 0.6rem 0.8rem; }

  /* Details/summary */
  details { margin-top: 0.75rem; }
  summary { cursor: pointer; font-size: 0.8rem; color: #64748b; padding: 0.25rem 0; }
  details ul { margin: 0.5rem 0 0 1.25rem; font-size: 0.8rem; color: #94a3b8; }
  details li { margin-bottom: 0.2rem; }

  /* No findings */
  .no-findings { background: #1e293b; border-radius: 0.75rem; padding: 3rem;
    text-align: center; color: #64748b; }

  /* Section headings */
  .section-heading { font-size: 1.1rem; font-weight: 700; color: #f1f5f9;
    margin: 1.5rem 0 1rem; padding-bottom: 0.4rem; border-bottom: 1px solid #334155; }
  .section-heading .count { color: #60a5fa; margin-left: 0.5rem; font-weight: 400; }
</style>
</head>
<body>

<div class="report-header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem">
    <div>
      <h1>IDOR Security Report — ${target}</h1>
      <p class="subtitle">
        <span class="tool-badge">${toolVersion}</span>
        Generated ${generatedAt}  ·  Only test systems you are authorized to test.
      </p>
    </div>
    <div style="text-align:right;font-size:0.8rem;color:#64748b">
      ${reportable.length > 0 ? `<div style="font-size:1.75rem;font-weight:700;color:#f87171">⚠ ${topSev} / CVSS ${topCvss}</div>` : ''}
    </div>
  </div>
</div>

<div class="stats-bar">
  <div class="stat-card stat-confirmed">
    <div class="stat-value">${s.confirmed || 0}</div>
    <div class="stat-label">Confirmed</div>
  </div>
  <div class="stat-card stat-likely">
    <div class="stat-value">${s.likely || 0}</div>
    <div class="stat-label">Likely</div>
  </div>
  <div class="stat-card stat-blocked">
    <div class="stat-value">${s.blocked || 0}</div>
    <div class="stat-label">Blocked</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#6b7280">${s.public || 0}</div>
    <div class="stat-label">Public</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#6b7280">${s.inconclusive || 0}</div>
    <div class="stat-label">Inconclusive</div>
  </div>
  ${reportable.length > 0 ? `
  <div class="stat-card stat-severity" style="margin-left:auto">
    <div class="stat-value">${topSev}</div>
    <div class="stat-label">Highest Severity (CVSS ${topCvss})</div>
  </div>` : ''}
</div>

<div class="main">

  ${(summary.confirmed || []).length > 0 ? `
  <div class="section-heading">Confirmed Cross-Tenant Reads <span class="count">${(summary.confirmed || []).length}</span></div>
  ${(summary.confirmed || []).map((r, i) => htmlFinding(r, i)).join('\n')}` : ''}

  ${(summary.likely || []).length > 0 ? `
  <div class="section-heading">Likely Cross-Tenant Reads <span class="count">${(summary.likely || []).length}</span></div>
  ${(summary.likely || []).map((r, i) => htmlFinding(r, (summary.confirmed || []).length + i)).join('\n')}` : ''}

  ${reportable.length === 0 ? findingsHtml : ''}

</div>

<script>
function toggle(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

// Auto-open confirmed findings.
document.addEventListener('DOMContentLoaded', () => {
  ${(summary.confirmed || []).map((_, i) => `document.getElementById('fd${i}')?.classList.add('open');`).join('\n  ')}
});

async function copyText(btn, preId) {
  const pre = document.getElementById(preId);
  if (!pre) return;
  try {
    await navigator.clipboard.writeText(pre.textContent || '');
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  } catch (e) {
    btn.textContent = 'Error';
  }
}
</script>
</body>
</html>`;
}
