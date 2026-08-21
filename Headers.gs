/**
 * Raw-message parsing. One fetch, one parse, per message.
 *
 * v1 called message.getRawContent() inside a single detector. v2 has four
 * detectors that need headers or body, so the raw content is fetched once into
 * a context object and passed down. Everything here is pure parsing — nothing
 * in this file makes a network call or touches Gmail state.
 */

/**
 * Splits a raw RFC-5322 message into unfolded headers and body.
 *
 * Gmail's getRawContent() sometimes normalizes CRLF to LF, so both boundaries
 * are tried (this was a real v1 bug — see CHANGELOG 2026-03-19).
 *
 * @param {string} raw
 * @returns {{h: Object<string, string[]>, headerBlock: string, body: string}}
 */
function parseRawMessage_(raw) {
  const empty = { h: {}, headerBlock: '', body: '' };
  if (!raw) return empty;

  let end = raw.indexOf('\r\n\r\n');
  let sepLen = 4;
  if (end <= 0) {
    end = raw.indexOf('\n\n');
    sepLen = 2;
  }

  const headerBlock = end > 0 ? raw.substring(0, end) : raw;
  const body = end > 0 ? raw.substring(end + sepLen) : '';

  // Unfold continuation lines before splitting — Received headers routinely
  // span four or five lines and are unparseable folded.
  const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, ' ');

  const h = {};
  const lines = unfolded.split(/\r?\n/);
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.substring(0, colon).trim().toLowerCase();
    if (!h[name]) h[name] = [];
    h[name].push(line.substring(colon + 1).trim());
  }

  return { h: h, headerBlock: headerBlock, body: body };
}

/**
 * Builds the per-message context every detector reads from.
 *
 * getRawContent() can throw (drafts, oversized messages, transient API errors).
 * That is not fatal: the context degrades to headers-absent and the detectors
 * that need headers simply produce no evidence.
 *
 * @param {GmailMessage} message
 * @returns {Object} context
 */
function buildMessageContext_(message) {
  let raw = '';
  try {
    raw = message.getRawContent() || '';
  } catch (e) {
    Logger.log('getRawContent failed: ' + e.message);
  }

  const parsed = parseRawMessage_(raw);

  let from = '';
  try {
    from = message.getFrom() || '';
  } catch (e) {
    from = '';
  }
  // getFrom() decodes RFC 2047 encoded-words; the raw header does not. Prefer
  // getFrom() and only fall back when it is unavailable.
  if (!from && parsed.h['from']) from = parsed.h['from'][0];

  const ctx = {
    message: message,
    from: from,
    raw: raw,
    headerBlock: parsed.headerBlock,
    body: parsed.body,
    headers: parsed.h,

    /** Last (topmost) value of a header, or '' — headers are stored top-down. */
    header: function (name) {
      const v = this.headers[name.toLowerCase()];
      return v && v.length ? v[0] : '';
    },
    /** All values of a header, in file order (top-down). */
    all: function (name) {
      return this.headers[name.toLowerCase()] || [];
    },
  };

  ctx.auth = parseAuthResults_(ctx);
  return ctx;
}

/**
 * Extracts SPF/DKIM/DMARC verdicts and the DKIM signing domain.
 *
 * These are recorded, never trusted as exoneration: a message relayed through a
 * compromised-but-authorized Workspace tenant passes all three. That separation
 * is the v2 thesis — see CHANGELOG.
 *
 * @param {Object} ctx
 * @returns {{spf: string, dkim: string, dmarc: string, dkimDomain: string, allPass: boolean}}
 */
function parseAuthResults_(ctx) {
  const ar = ctx.all('authentication-results').join(' ; ');
  const pick = function (re) {
    const m = ar.match(re);
    return m ? m[1].toLowerCase() : '';
  };

  const spf = pick(/\bspf=(\w+)/);
  const dkim = pick(/\bdkim=(\w+)/);
  const dmarc = pick(/\bdmarc=(\w+)/);

  // Prefer the domain the Authentication-Results header attributes DKIM to;
  // fall back to the d= tag on the signature itself.
  let dkimDomain = '';
  const arDomain = ar.match(/\bdkim=pass[^;]*?\bheader\.i=@?([A-Za-z0-9.-]+)/) ||
    ar.match(/\bdkim=pass[^;]*?\bheader\.d=([A-Za-z0-9.-]+)/);
  if (arDomain) {
    dkimDomain = arDomain[1].toLowerCase();
  } else {
    const sig = ctx.header('dkim-signature');
    const d = sig ? sig.match(/(?:^|[;\s])d=([A-Za-z0-9.-]+)/) : null;
    if (d) dkimDomain = d[1].toLowerCase();
  }

  return {
    spf: spf,
    dkim: dkim,
    dmarc: dmarc,
    dkimDomain: dkimDomain,
    allPass: spf === 'pass' && dkim === 'pass' && dmarc === 'pass',
  };
}
