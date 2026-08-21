/**
 * Core spoof-detection logic: parse sender, normalize, compare domains.
 */

const WHITELIST_PROPERTY_KEY = 'senderWhitelist';

/**
 * Platform domains commonly abused to send phishing emails.
 * Emails from subdomains of these are flagged as suspicious.
 */
const SUSPICIOUS_PLATFORMS = [
  'firebaseapp.com',
  'appspot.com',
];

/**
 * DKIM selectors used by suspicious platforms.
 * Catches custom-domain emails sent through these platforms (e.g., Firebase with a
 * registered domain instead of *.firebaseapp.com).
 */
const SUSPICIOUS_DKIM_SELECTORS = [
  { platform: 'firebase', pattern: /(?:header\.s|\bs)=firebase1\b/ },
];

/**
 * Root domains of services legitimately allowed to put the recipient's own
 * organization name/domain in the From display name (form-service and
 * on-behalf-of notifications, e.g. Netlify Forms, DocuSign). Matched against
 * the root domain of the From address itself (not display-name content). As
 * with every other check in this file, this trusts the From address and does
 * not itself verify DKIM/SPF alignment.
 */
const OWNER_REF_ALLOWED_SERVICES = [
  'netlify.com',
  'formspree.io',
  'google.com',
  'docusign.net',
];

/**
 * Checks if a sender domain is a subdomain of a known suspicious platform.
 * @param {string} emailDomain - e.g., "kriyiasahbi.firebaseapp.com"
 * @returns {string|null} The matched platform or null
 */
function isSuspiciousPlatform(emailDomain) {
  if (!emailDomain) return null;
  const domain = emailDomain.toLowerCase();
  for (const platform of SUSPICIOUS_PLATFORMS) {
    if (domain === platform || domain.endsWith('.' + platform)) {
      return platform;
    }
  }
  return null;
}

/**
 * Checks the raw message headers for DKIM selectors associated with suspicious platforms.
 * This catches emails sent via platforms like Firebase using a custom domain
 * (e.g., noreply@qgui777com.com with DKIM selector "firebase1").
 * @param {Object} ctx - Message context from buildMessageContext_()
 * @returns {string|null} The matched platform name or null
 */
function checkSuspiciousDkimSelector(ctx) {
  if (!ctx || !ctx.headerBlock) return null;
  for (const entry of SUSPICIOUS_DKIM_SELECTORS) {
    if (entry.pattern.test(ctx.headerBlock)) {
      return entry.platform;
    }
  }
  return null;
}

/** @type {string[]|null} */
let _whitelistCache = null;

/** @type {string|null} */
let _ownerDomainCache = null;

/**
 * Returns the inbox owner's root domain (cached per execution).
 * Used to recognize legitimate notifications about the recipient's own domain
 * (e.g., form-service emails like Netlify Forms that put the customer's domain
 * in the display name).
 * @returns {string}
 */
function getOwnerDomain_() {
  if (_ownerDomainCache !== null) return _ownerDomainCache;
  try {
    const email = (Session.getEffectiveUser().getEmail() ||
      Session.getActiveUser().getEmail() || '').toLowerCase();
    const domain = email.split('@')[1] || '';
    _ownerDomainCache = domain ? extractRootDomain(domain) : '';
  } catch (e) {
    _ownerDomainCache = '';
  }
  return _ownerDomainCache;
}

/**
 * Returns the sender whitelist from Script Properties (cached per execution).
 * @returns {string[]}
 */
function getWhitelist_() {
  if (_whitelistCache !== null) return _whitelistCache;
  try {
    const raw = PropertiesService.getScriptProperties().getProperty(WHITELIST_PROPERTY_KEY);
    _whitelistCache = raw ? JSON.parse(raw) : [];
  } catch (e) {
    _whitelistCache = [];
  }
  return _whitelistCache;
}

/**
 * Checks if a sender email is whitelisted by address, full domain, or root domain.
 * @param {string} email
 * @returns {boolean}
 */
function isSenderWhitelisted(email) {
  if (!email) return false;
  const whitelist = getWhitelist_();
  if (whitelist.length === 0) return false;

  const domain = email.split('@')[1];
  if (!domain) return false;
  const root = extractRootDomain(domain);

  for (const entry of whitelist) {
    if (entry === email || entry === domain || entry === root) return true;
  }
  return false;
}

/**
 * Parses a "From" header string into display name and email.
 * Handles formats:
 *   "Display Name" <email@domain.com>
 *   Display Name <email@domain.com>
 *   email@domain.com
 * @param {string} fromString
 * @returns {{displayName: string, email: string}}
 */
function parseSender(fromString) {
  if (!fromString) return { displayName: '', email: '' };

  // Try "Name" <email> or Name <email>
  const match = fromString.match(/^"?(.+?)"?\s*<([^>]+)>$/);
  if (match) {
    return { displayName: match[1].trim(), email: match[2].trim().toLowerCase() };
  }

  // Bare email address
  const emailOnly = fromString.trim().toLowerCase();
  return { displayName: '', email: emailOnly };
}

/**
 * Extracts the root domain from a full domain string.
 * Handles compound TLDs like .co.il, .co.uk, .com.au, .org.il.
 * @param {string} domain - e.g., "mail.wix.com" or "info.leumi.co.il"
 * @returns {string} - e.g., "wix.com" or "leumi.co.il"
 */
function extractRootDomain(domain) {
  if (!domain) return '';
  const parts = domain.toLowerCase().split('.');
  if (parts.length <= 2) return domain.toLowerCase();

  // Compound TLDs: if second-to-last segment is 2 chars or fewer (co, ac, or, ne, etc.)
  const secondToLast = parts[parts.length - 2];
  if (secondToLast.length <= 2) {
    // Take last 3 segments (e.g., leumi.co.il)
    return parts.slice(-3).join('.');
  }

  // Standard TLD: take last 2 segments (e.g., wix.com)
  return parts.slice(-2).join('.');
}

/**
 * Tries to extract a domain-like pattern from a display name after homoglyph normalization.
 * Looks for patterns like "word.tld" in the normalized text.
 * @param {string} displayName - Raw display name (may contain homoglyphs)
 * @returns {string|null} - Extracted domain or null
 */
function extractDomainFromDisplayName(displayName) {
  if (!displayName) return null;

  const normalized = normalizeToAscii(displayName);

  // Match domain-like patterns: word.word or word.word.word
  const domainPattern = /([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}/g;
  const match = normalized.match(domainPattern);

  return match ? match[0] : null;
}

/**
 * Detects an external sender wearing the inbox owner's own organizational
 * identity in the From display name — internal-impersonation phishing such as
 * "Docs@theroadtlv" <documents@asecureltd.com>.
 *
 * The owner's org label (e.g. "theroadtlv" from "theroadtlv.com") is matched as
 * a whole word after homoglyph normalization, so it fires on the bare token,
 * the @-styled form, and the full domain alike (@ and . are non-word characters,
 * so the \b boundaries hold). The message passes when the sender is the owner's
 * own aligned domain (genuinely internal) or a recognized on-behalf-of service.
 *
 * This check is authoritative for owner-domain references: it either flags the
 * message or intentionally clears it. The generic check at step 5b defers to it
 * via the kept owner-domain skip.
 *
 * @param {{displayName: string, email: string}} sender - parsed From
 * @param {string} from - raw From header string (for details)
 * @returns {{isSpoof: boolean, reason: string, brand: string, details: string}|null}
 */
function checkOwnerImpersonation(sender, from) {
  const ownerRoot = getOwnerDomain_();
  if (!ownerRoot) return null;

  const ownerToken = ownerRoot.split('.')[0];
  if (ownerToken.length < 4) return null; // too short to word-match safely

  if (!sender.displayName) return null;
  const normalized = normalizeToAscii(sender.displayName).toLowerCase();

  // Owner org labels contain only [a-z0-9-], none of which are regex
  // metacharacters, so the token is safe to embed directly.
  // Whole-word match of the org label. Because @ and . are non-word characters,
  // \b covers the bare token, the @-styled form, and the full domain alike.
  const tokenPattern = new RegExp('\\b' + ownerToken + '\\b');
  if (!tokenPattern.test(normalized)) return null;

  const senderDomain = sender.email.split('@')[1];
  if (!senderDomain) return null;
  const senderRoot = extractRootDomain(senderDomain);

  if (senderRoot === ownerRoot) return null; // genuinely internal
  if (OWNER_REF_ALLOWED_SERVICES.indexOf(senderRoot) !== -1) return null; // legit on-behalf-of

  return {
    isSpoof: true,
    brand: ownerToken,
    reason: 'Display name impersonates your own domain (' + ownerToken +
      ') but email is from ' + senderRoot,
    details: 'From: ' + from + ' | Owner: ' + ownerRoot + ' | Actual: ' + senderRoot,
  };
}

/**
 * Scoring. Weights are chosen so that any one "hard" detector alone crosses
 * SPOOF_SCORE_THRESHOLD — that is v1 behaviour, deliberately kept — while the
 * scored signals (D2 display-name obfuscation, D4 MUA fingerprint) cannot flag
 * a message on their own. Two independent scored families together can.
 *
 * The arithmetic exists to make "authenticated and anomalous" reachable, not to
 * replace the hard checks. A bare score is not actionable, so every verdict
 * carries its evidence list.
 */
const WEIGHT_HARD = 100;
const SPOOF_SCORE_THRESHOLD = 50;

/**
 * Scored detectors contribute at most this much each, which is below the
 * threshold by construction: no amount of piled-up display-name weirdness flags
 * a message by itself, but weirdness plus a scripted-mailer fingerprint does.
 */
const SCORED_FAMILY_CAP = 45;
const SCORED_DETECTORS = ['D2', 'D4'];
const SEVERITY_TIERS = [
  { min: 150, name: 'CRITICAL' },
  { min: 100, name: 'HIGH' },
  { min: SPOOF_SCORE_THRESHOLD, name: 'WATCH' },
];

/**
 * Builds one evidence entry.
 * @param {string} detector - Detector id, e.g. 'D1' or 'owner-impersonation'
 * @param {number} weight
 * @param {string} note - Human-readable, shown in alerts
 * @param {Object} [extra] - Optional {brand, details}
 * @returns {{detector: string, weight: number, note: string, brand: string, details: string}}
 */
function evidence_(detector, weight, note, extra) {
  extra = extra || {};
  return {
    detector: detector,
    weight: weight,
    note: note,
    brand: extra.brand || '',
    details: extra.details || '',
  };
}

/**
 * Collapses an evidence list into the verdict object callers consume.
 * `isSpoof` is retained as a derived field so v1 call sites keep working.
 * @param {Array} evidence
 * @param {string} from
 * @returns {{isSpoof: boolean, score: number, severity: string, reason: string, brand: string, details: string, evidence: Array}}
 */
function verdict_(evidence, from) {
  const perDetector = {};
  for (const e of evidence) {
    perDetector[e.detector] = (perDetector[e.detector] || 0) + e.weight;
  }
  let score = 0;
  for (const detector in perDetector) {
    score += SCORED_DETECTORS.indexOf(detector) !== -1
      ? Math.min(perDetector[detector], SCORED_FAMILY_CAP)
      : perDetector[detector];
  }

  // Strongest signal becomes the headline. Array.sort is stable in V8, so
  // detectors of equal weight keep the order they fired in.
  evidence = evidence.slice().sort(function (a, b) { return b.weight - a.weight; });

  let severity = '';
  for (const tier of SEVERITY_TIERS) {
    if (score >= tier.min) {
      severity = tier.name;
      break;
    }
  }

  const isSpoof = score >= SPOOF_SCORE_THRESHOLD;
  const primary = evidence.length ? evidence[0] : null;
  const reason = !primary ? '' :
    primary.note + (evidence.length > 1 ? ' (+' + (evidence.length - 1) + ' more signal' +
      (evidence.length > 2 ? 's' : '') + ')' : '');

  const details = evidence.length
    ? 'From: ' + from + ' | score ' + score + ' ' + severity + ' | ' +
      evidence.map(function (e) {
        return e.detector + '(' + e.weight + '): ' + (e.details || e.note);
      }).join(' | ')
    : '';

  return {
    isSpoof: isSpoof,
    score: score,
    severity: severity,
    reason: reason,
    brand: primary ? primary.brand : '',
    details: details,
    evidence: evidence,
  };
}

/**
 * Main spoof-detection check for a single Gmail message.
 *
 * Order matters: the scored signals are collected first so they appear in the
 * evidence list even when a hard check fires and short-circuits. The hard chain
 * itself preserves v1's exact sequence, including its deliberate clearing
 * returns (a legitimate brand-domain match stops the chain clean).
 *
 * @param {GmailMessage} message
 * @returns {{isSpoof: boolean, score: number, severity: string, reason: string, brand: string, details: string, evidence: Array}}
 */
function checkForSpoof(message) {
  // Parse the From header before fetching raw content: v2 needs the full
  // message for D3/D4/D5, and getRawContent() is the expensive call in the
  // scan. Whitelisted and address-less senders skip it entirely.
  const from = message.getFrom() || '';
  const sender = parseSender(from);
  const evidence = [];

  if (!sender.email) return verdict_(evidence, from);
  if (isSenderWhitelisted(sender.email)) return verdict_(evidence, from);

  const ctx = buildMessageContext_(message);

  // The brand match is computed once here rather than inside the hard chain:
  // D5 needs to know which brand is being claimed in order to judge whether a
  // link target is unrelated to it.
  const brandMatch = identifyBrand_(sender);

  collectSignals_(ctx, sender, brandMatch, evidence);

  const hard = runHardChecks_(ctx, sender, brandMatch);
  if (hard) evidence.push(hard);

  return verdict_(evidence, ctx.from);
}

/**
 * Finds the brand a sender claims to be, from the display name first and the
 * email local part second.
 * @param {{displayName: string, email: string}} sender
 * @returns {Object|null}
 */
function identifyBrand_(sender) {
  const normalizedName = sender.displayName ? normalizeToAscii(sender.displayName) : '';
  const byName = findSpoofedBrand(normalizedName);
  if (byName) return byName;
  const localPart = sender.email.split('@')[0].replace(/[._+-]/g, ' ');
  return findSpoofedBrand(localPart);
}

/**
 * Runs the detectors that contribute evidence without terminating the chain.
 * D2 and D4 are always scored-only. D3 and D5 can each emit a hard-weight
 * entry, but they still run to completion so their other signals are recorded.
 * @param {Object} ctx
 * @param {{displayName: string, email: string}} sender
 * @param {Object|null} brandMatch
 * @param {Array} evidence - Mutated in place
 */
function collectSignals_(ctx, sender, brandMatch, evidence) {
  const pushAll = function (list) {
    for (const e of list) evidence.push(e);
  };
  pushAll(checkDisplayNameObfuscation_(sender));
  pushAll(checkMuaFingerprint_(ctx, sender));
  pushAll(checkReceivedChain_(ctx, sender));
  pushAll(checkLinks_(ctx, sender, brandMatch));
}

/**
 * The v1 detector chain: first hit wins, and several checks deliberately clear
 * the message rather than fall through.
 * @param {Object} ctx
 * @param {{displayName: string, email: string}} sender
 * @param {Object|null} brandMatch - Result of identifyBrand_()
 * @returns {Object|null} An evidence entry, or null if nothing fired
 */
function runHardChecks_(ctx, sender, brandMatch) {
  const from = ctx.from;
  const senderDomain = sender.email.split('@')[1];

  // 1. Sender is on a platform routinely abused to send phishing.
  const suspiciousPlatform = isSuspiciousPlatform(senderDomain);
  if (suspiciousPlatform) {
    return evidence_('platform', WEIGHT_HARD,
      'Sent from suspicious platform: ' + suspiciousPlatform,
      { brand: suspiciousPlatform, details: 'Platform domain: ' + senderDomain });
  }

  // 2. Platform DKIM selector on a custom domain (e.g. Firebase's "firebase1").
  const dkimPlatform = checkSuspiciousDkimSelector(ctx);
  if (dkimPlatform) {
    return evidence_('dkim-selector', WEIGHT_HARD,
      'Sent via suspicious platform: ' + dkimPlatform + ' (custom domain)',
      { brand: dkimPlatform, details: 'Sender domain: ' + senderDomain });
  }

  // 3. Owner-domain impersonation. Authoritative for owner-domain references:
  //    it either flags or intentionally clears, and the generic check below
  //    defers to it via the kept owner-domain skip.
  const ownerSpoof = checkOwnerImpersonation(sender, from);
  if (ownerSpoof) {
    return evidence_('owner-impersonation', WEIGHT_HARD, ownerSpoof.reason,
      { brand: ownerSpoof.brand, details: ownerSpoof.details });
  }

  if (!senderDomain) return null;
  const actualRoot = extractRootDomain(senderDomain);
  const dkimRoot = ctx.auth.dkimDomain ? extractRootDomain(ctx.auth.dkimDomain) : '';

  // 4. Generic: display name carries a domain that is not the sender's.
  //    Catches brands that are not on the list at all.
  if (!brandMatch) {
    const impliedDomain = extractDomainFromDisplayName(sender.displayName);
    if (!impliedDomain) return null;
    const impliedRoot = extractRootDomain(impliedDomain);

    // Form-service notifications (Netlify Forms, Formspree, ...) legitimately
    // put the recipient's own domain in the display name. Phishing impersonates
    // other brands, not your own domain to you — and the owner-impersonation
    // check above already owns that case.
    const ownerDomain = getOwnerDomain_();
    if (ownerDomain && impliedRoot === ownerDomain) return null;

    if (impliedRoot !== actualRoot && !isRelatedBrandDomain(impliedRoot, actualRoot)) {
      return evidence_('generic-domain', WEIGHT_HARD,
        'Display name contains domain ' + impliedDomain + ' but email is from ' + actualRoot,
        {
          brand: impliedRoot.split('.')[0],
          details: 'Display domain: ' + impliedDomain + ' | Actual domain: ' + actualRoot,
        });
    }
    return null;
  }

  // 5. A brand was identified. It is legitimate if either the From domain or
  //    the DKIM signing domain belongs to that brand. Checking both is D1's
  //    other half: a relayed message can sign as the brand while the From
  //    domain differs, and vice versa.
  const brandRoot = extractRootDomain(brandMatch.domain);
  for (const root of [actualRoot, dkimRoot]) {
    if (!root) continue;
    if (root === brandRoot || isRelatedBrandDomain(brandRoot, root)) return null;
  }

  // 6. A display name that carries the sender's own domain is self-consistent,
  //    whatever brand token it also happens to contain.
  const impliedDomain = extractDomainFromDisplayName(sender.displayName);
  if (impliedDomain && extractRootDomain(impliedDomain) === actualRoot) return null;

  const how = brandMatch.match && brandMatch.match !== 'domain' && brandMatch.match !== 'token'
    ? ' via ' + brandMatch.match + ' match "' + brandMatch.matched + '"'
    : '';
  return evidence_('D1', WEIGHT_HARD,
    'Display name impersonates ' + brandMatch.domain + how + ' but email is from ' + actualRoot,
    {
      brand: brandMatch.brandName,
      details: 'Normalized: ' + normalizeToAscii(sender.displayName) + ' | Actual domain: ' + actualRoot +
        (dkimRoot && dkimRoot !== actualRoot ? ' | DKIM d=' + dkimRoot : '') +
        ' | match: ' + (brandMatch.match || 'exact'),
    });
}
