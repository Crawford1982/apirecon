/**
 * Shape-based classification of path/query segment values as potential
 * object identifiers (IDs) for IDOR hunting.
 *
 * This file is intentionally standalone so it can be unit-tested and
 * reused by both the detector and the report generator.
 */

/**
 * Resource-name tokens that look ID-ish (mostly alphanumeric) but are
 * actually English words / action nouns and should never be treated as IDs.
 *
 * Matching is case-insensitive, separator-agnostic (-/_/.).
 */
const RESOURCE_WORDS = new Set([
  'notifications',
  'notification',
  'metadata',
  'appmetadata',
  'contentresourceajax',
  'settings',
  'dashboard',
  'overview',
  'detail',
  'details',
  'home',
  'history',
  'all',
  'list',
  'create',
  'new',
  'edit',
  'export',
  'download',
  'upload',
  'search',
  'filter',
  'help',
  'logout',
  'login',
  'register',
  'signup',
  'feed',
  'stream',
  'streams',
  'research',
  'survey',
  'surveys',
  'health',
  'healthreports',
  'ancestry',
  'ancestryoverview',
  'ancestrycomposition',
  'traits',
  'wellness',
  'reports',
  'report',
  'results',
  'dna',
  'dnarelatives',
  'relatives',
  'relative',
  'billing',
  'account',
  'profile',
  'profiles',
  'inbox',
  'messages',
  'cart',
  'checkout',
  'onboarding',
  'tour',
  'faq',
  'about',
  'privacy',
  'terms',
  'questionstreamitem',
  'questionstream',
  'allquestionsdatafordashboard',
  'allquestionsdashboard',
  'dashboardquestions',
  'questionnaire',
  'questions',
  'ajax',
  'api',
  'v1',
  'v2',
  'v3',
  'static',
  'assets',
  'images',
  'img',
  'css',
  'js',
  'fonts',
  'tracking',
  'analytics',
  'events',
  'telemetry',
  'session',
  'auth',
  'authorize',
  'authcallback',
  'callback',
  'consent',
  'page',
  'pages',
  'index',
  'true',
  'false',
  'null',
  'undefined',
]);

/**
 * Dictionary of English-ish stems for heuristic "this looks like a word" detection.
 * Cheap – we don't need lexical correctness, just enough to filter obvious
 * resource names like "recommended_surveys".
 */
// NOTE: we intentionally don't use \b boundaries because underscores are
// word characters, so `\bquestion\b` wouldn't match `questions` inside
// `all_questions_dashboard`. We accept broad substring matches instead —
// false positives are fine here since this only filters *resource name*
// tokens that wouldn't otherwise look like IDs.
const WORDY_STEMS =
  /(user|profile|account|setting|dashboard|home|research|survey|recommend|content|resource|notification|metadata|report|relative|dna|health|ancestry|billing|order|payment|session|auth|login|logout|download|upload|export|import|search|filter|create|update|delete|list|all|detail|new|edit|page|stream|question|answer|result|data|response|request|item|value|config|admin|token|refresh|access)/i;

/** Keys that never identify a single resource and never warrant IDOR probing. */
const PAGINATION_KEYS_RAW = [
  'page',
  'pagesize',
  'pageindex',
  'perpage',
  'pagesize',
  'limit',
  'offset',
  'size',
  'count',
  'max',
  'start',
  'end',
  'from',
  'to',
  'skip',
  'take',
  'after',
  'before',
  'next',
  'prev',
  'previous',
  'cursor',
  'sort',
  'order',
  'orderby',
  'direction',
  'asc',
  'desc',
  'q',
  'query',
  'search',
  'filter',
  'fields',
  'expand',
  'include',
  'exclude',
  'embed',
  'callback',
  'format',
  'output',
  'view',
  'mode',
  'locale',
  'lang',
  'lng',
  'region',
  'country',
  'currency',
  'location',
  'category',
  'type',
  'kind',
  'status',
  'state',
  'role',
  'nonce',
  'timestamp',
  't',
  'ts',
  'v',
  'ver',
  'version',
  'cb',
  'ref',
  'source',
  'utmsource',
  'utmmedium',
  'utmcampaign',
  'utmcontent',
  'utmterm',
  'gclid',
  'fbclid',
  'platform',
  'device',
  'app',
  'client',
  'channel',
  'section',
  'tab',
  'step',
  'variant',
  'theme',
  'rand',
  'random',
];

export const PAGINATION_KEYS = new Set(PAGINATION_KEYS_RAW);

/**
 * Keys whose *name* strongly implies an object identifier. We still require
 * the value to look like an ID too (see {@link classifyValue}).
 */
const ID_NAMES_RAW = [
  'id',
  'ids',
  'uid',
  'uuid',
  'guid',
  'userid',
  'profileid',
  'accountid',
  'customerid',
  'memberid',
  'relativeid',
  'orderid',
  'reportid',
  'participantid',
  'sampleid',
  'kitid',
  'subscriptionid',
  'subid',
  'entityid',
  'objectid',
  'resourceid',
  'itemid',
  'productid',
  'skuid',
  'sku',
  'testid',
  'variantid',
  'genotypeid',
  'orgid',
  'organizationid',
  'teamid',
  'tenantid',
  'sessionid',
  'requestid',
  'transactionid',
  'paymentid',
  'invoiceid',
  'addressid',
  'noteid',
  'messageid',
  'commentid',
  'postid',
  'threadid',
  'ownerid',
  'authorid',
  'creatorid',
  'sharedwith',
  'targetuser',
  'targetprofile',
];

export const ID_NAMES = new Set(ID_NAMES_RAW);

/**
 * Path path-segment words that indicate the *next* segment identifies an
 * object (a "scope"). The scope's ID is a top-priority IDOR target.
 */
const SCOPE_WORDS_RAW = [
  'p',
  'profile',
  'profiles',
  'user',
  'users',
  'account',
  'accounts',
  'member',
  'members',
  'customer',
  'customers',
  'relative',
  'relatives',
  'sample',
  'samples',
  'kit',
  'kits',
  'order',
  'orders',
  'subscription',
  'subscriptions',
  'organization',
  'organizations',
  'org',
  'team',
  'teams',
  'tenant',
  'tenants',
  'group',
  'groups',
  'report',
  'reports',
  'sharedwith',
  'share',
  'shares',
  'payment',
  'payments',
  'invoice',
  'invoices',
  'address',
  'addresses',
  'participant',
  'participants',
];

export const SCOPE_WORDS = new Set(SCOPE_WORDS_RAW);

/**
 * Normalise a key for case-insensitive, separator-agnostic matching.
 * `page-size` / `Page_Size` / `pageSize` -> `pagesize`.
 *
 * @param {string} key
 */
export function normKey(key) {
  return String(key || '')
    .toLowerCase()
    .replace(/[\s\-_.]/g, '');
}

/** @param {string} key */
export function isPaginationKey(key) {
  return PAGINATION_KEYS.has(normKey(key));
}

/** @param {string} key */
export function isIdName(key) {
  return ID_NAMES.has(normKey(key));
}

/** @param {string} segment */
export function isScopeWord(segment) {
  return SCOPE_WORDS.has(normKey(segment));
}

/** @param {string} token */
export function isResourceWord(token) {
  return RESOURCE_WORDS.has(normKey(token));
}

/**
 * Does this token *look* like an English word rather than an opaque ID?
 *
 * Cheap heuristic: lowercase alpha-only, ≤ 20 chars, contains a vowel,
 * consonant runs stay short. If multiple segments (separated by `-`/`_`),
 * each gets the same test AND at least one segment matches WORDY_STEMS.
 *
 * @param {string} token
 */
export function looksLikeWord(token) {
  if (!token) return false;
  const s = String(token);
  if (s.length > 40) return false;
  // Strings that are entirely hex and long enough to be an ID are never
  // treated as words, even if they happen to contain vowel-like letters
  // (e.g. "deadbeef").
  if (/^[a-fA-F0-9]+$/.test(s) && s.length >= 6) return false;
  const parts = s.split(/[-_.]/).filter(Boolean);
  if (parts.length === 0) return false;

  const wordy = (seg) => {
    if (!/^[A-Za-z]+$/.test(seg)) return false;
    if (seg.length > 20) return false;
    const vowels = (seg.match(/[aeiouy]/gi) || []).length;
    if (vowels === 0) return false;
    const longConsonantRun = /[bcdfghjklmnpqrstvwxz]{5,}/i.test(seg);
    return !longConsonantRun;
  };

  const allSegsWordy = parts.every(wordy);
  if (!allSegsWordy) return false;
  if (parts.length === 1) return true;
  return WORDY_STEMS.test(s);
}

/**
 * Shape-classify a raw value as a potential object identifier.
 *
 * Returns {@link null} when the value isn't plausibly an ID (too short,
 * too long, obvious resource noun, pagination-looking, etc.).
 *
 * Risk levels returned here are *base* risks for the shape only; the
 * caller composes context (method, path nouns, name match) on top.
 *
 * @param {string} raw
 * @returns {{ shape: string, risk: number } | null}
 */
export function classifyValue(raw) {
  if (raw == null) return null;
  const v = String(raw);
  if (!v) return null;
  if (v.length > 200) return null;
  if (v.includes('/') || v.includes('?') || v.includes('&') || v.includes('=')) {
    return null;
  }

  if (isResourceWord(v)) return null;

  // "word + short version suffix" — e.g. items2, api3, v10. These are
  // resource/version tokens, not object IDs.
  if (/^[A-Za-z]+\d{1,2}$/.test(v) && v.length <= 12) return null;

  if (/^\d{1,3}$/.test(v)) return { shape: 'numeric-short', risk: 2 };
  if (/^\d{4,6}$/.test(v)) return { shape: 'numeric-medium', risk: 3 };
  if (/^\d{7,12}$/.test(v)) return { shape: 'numeric-long', risk: 4 };
  if (/^\d{13,19}$/.test(v)) return { shape: 'snowflake', risk: 4 };

  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(v)) {
    return { shape: 'uuid', risk: 4 };
  }

  if (/^[a-f0-9]{64}$/i.test(v)) return { shape: 'hex-64', risk: 3 };
  if (/^[a-f0-9]{40}$/i.test(v)) return { shape: 'hex-40', risk: 4 };
  if (/^[a-f0-9]{32}$/i.test(v)) return { shape: 'hex-32', risk: 4 };
  if (/^[a-f0-9]{16}$/i.test(v)) return { shape: 'hex-16', risk: 5 };
  if (/^[a-f0-9]{12}$/i.test(v)) return { shape: 'hex-12', risk: 4 };
  if (/^[a-f0-9]{8}$/i.test(v)) return { shape: 'hex-8', risk: 3 };

  if (/^[A-Za-z0-9_-]{22,}$/.test(v) && !/^[A-Za-z]+$/.test(v) && !looksLikeWord(v)) {
    const hasDigit = /\d/.test(v);
    return { shape: 'opaque-token', risk: hasDigit ? 4 : 3 };
  }

  if (/^[A-Za-z0-9_-]{6,21}$/.test(v) && /\d/.test(v) && !looksLikeWord(v)) {
    return { shape: 'opaque-short', risk: 3 };
  }

  return null;
}
