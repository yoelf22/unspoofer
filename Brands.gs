/**
 * Brand/domain list and matching logic for spoof detection.
 */

const BRAND_DOMAINS = [
  // Tech giants
  'google.com', 'apple.com', 'microsoft.com', 'amazon.com', 'meta.com',
  'facebook.com', 'instagram.com', 'whatsapp.com',

  // AI
  'openai.com', 'chatgpt.com',

  // Cloud / SaaS
  'wix.com', 'squarespace.com', 'shopify.com', 'godaddy.com',
  'dropbox.com', 'zoom.us', 'slack.com', 'notion.so',
  'salesforce.com', 'hubspot.com', 'mailchimp.com',

  // Email / comms
  'outlook.com', 'yahoo.com', 'protonmail.com',

  // Payments
  'paypal.com', 'stripe.com', 'wise.com', 'revolut.com', 'venmo.com',
  'square.com',

  // Streaming / media
  'netflix.com', 'spotify.com', 'youtube.com', 'twitch.tv',
  'linkedin.com', 'twitter.com', 'x.com',

  // Shipping
  'fedex.com', 'ups.com', 'dhl.com', 'usps.com',

  // US banks
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
  'capitalone.com',

  // Israeli banks
  'leumi.co.il', 'poalim.co.il', 'discount.co.il', 'mizrahi-tefahot.co.il',
  'fibi.co.il',

  // Israeli services
  'walla.co.il', 'ynet.co.il', 'gett.com',

  // E-signature / documents
  'docusign.com', 'adobe.com',

  // Security / infra
  'cloudflare.com', 'github.com', 'gitlab.com',

  // E-commerce
  'ebay.com', 'aliexpress.com', 'etsy.com',
];

/**
 * Groups of related domains owned by the same company.
 * If a display name matches brand X and the sender is from a related domain, it's legitimate.
 */
const BRAND_GROUPS = [
  ['google.com', 'youtube.com', 'googlemail.com'],
  ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'office.com', 'office365.com'],
  ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
  ['meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com'],
  ['amazon.com', 'amazonaws.com'],
  ['openai.com', 'chatgpt.com'],
  ['docusign.com', 'docusign.net'],
];

/**
 * Gates for near-miss matching (D1). See findNearMissBrand_ for why these
 * numbers and not smaller ones.
 */
const BRAND_AFFIX_MIN_LEN = 6;
const BRAND_AFFIX_MAX_EXTRA = 3;
const BRAND_FUZZY_MIN_LEN = 8;
const BRAND_FUZZY_MAX_DISTANCE = 2;

let _relatedDomainCache = null;

/**
 * Checks if two root domains belong to the same brand group.
 * @param {string} brandRoot
 * @param {string} senderRoot
 * @returns {boolean}
 */
function isRelatedBrandDomain(brandRoot, senderRoot) {
  if (!_relatedDomainCache) {
    _relatedDomainCache = {};
    for (const group of BRAND_GROUPS) {
      const roots = group.map(d => extractRootDomain(d));
      for (const root of roots) {
        _relatedDomainCache[root] = roots;
      }
    }
  }
  const related = _relatedDomainCache[brandRoot];
  return related ? related.includes(senderRoot) : false;
}

/**
 * Extracts the bare brand name from a domain (e.g., "paypal.com" → "paypal").
 * @param {string} domain
 * @returns {string}
 */
function extractBrandName(domain) {
  return domain.split('.')[0];
}

/**
 * Checks if a normalized display name contains a known brand domain or brand name.
 * Returns the matched brand domain or null.
 * @param {string} normalizedDisplayName - Already normalized (ASCII, lowercase)
 * @returns {{domain: string, brandName: string}|null}
 */
function findSpoofedBrand(normalizedDisplayName) {
  if (!normalizedDisplayName) return null;

  for (const domain of BRAND_DOMAINS) {
    // Check for full domain match (e.g., "wix.com" in display name)
    if (normalizedDisplayName.includes(domain)) {
      return { domain: domain, brandName: extractBrandName(domain), match: 'domain', matched: domain };
    }
  }

  // Second pass: check bare brand names (e.g., "paypal" without .com)
  // Only match standalone-looking brand names (word boundary approximation)
  for (const domain of BRAND_DOMAINS) {
    const brand = extractBrandName(domain);
    if (brand.length < 2) continue; // Skip single-char names like "x" to avoid false positives
    const idx = normalizedDisplayName.indexOf(brand);
    if (idx !== -1) {
      // Basic word-boundary check: brand shouldn't be a substring of a longer word
      const before = idx > 0 ? normalizedDisplayName[idx - 1] : ' ';
      const after = idx + brand.length < normalizedDisplayName.length
        ? normalizedDisplayName[idx + brand.length]
        : ' ';
      const isBoundary = (ch) => /[^a-z0-9]/.test(ch);
      if (isBoundary(before) && isBoundary(after)) {
        return { domain: domain, brandName: brand, match: 'token', matched: brand };
      }
    }
  }

  // Third pass (D1): near-miss forms that the exact passes above reject by
  // design — glued affixes ("edocusign"), separator-split brands ("docu-sign"),
  // and small typos ("micr0soft").
  return findNearMissBrand_(normalizedDisplayName);
}

/**
 * D1 — near-miss brand matching.
 *
 * Two rules, both deliberately gated by brand length. The gates are the whole
 * reason this is safe to run against a live inbox:
 *
 *  - Affix (brands >= 6 chars): the candidate contains the brand with at most 3
 *    extra characters, and the extra characters are not an English suffix — see
 *    affixIsDeceptive_. Shorter brands are excluded because "groups" contains
 *    "ups" and "metal" contains "meta".
 *  - Edit distance <= 2 (brands >= 8 chars): at 6 chars real words collide
 *    ("notice" is distance 2 from "notion"); 8 is where that stops.
 *
 * ponytail: length gates, not a dictionary. Means 7-char brands (netflix,
 * spotify, youtube) get affix matching but no typo matching. Add a common-word
 * stoplist and lower the fuzzy gate to 6 if typo-squatting on those shows up.
 *
 * @param {string} normalized - Already normalized (ASCII, lowercase)
 * @returns {{domain: string, brandName: string, match: string, matched: string}|null}
 */
function findNearMissBrand_(normalized) {
  const candidates = brandCandidates_(normalized);
  if (candidates.length === 0) return null;

  for (const domain of BRAND_DOMAINS) {
    const brand = extractBrandName(domain);
    for (const cand of candidates) {
      // An exact match reaching here means separators hid it from pass 2
      // ("docu-sign" tokenizes apart, then rejoins as a pair candidate).
      if (cand === brand) {
        return { domain: domain, brandName: brand, match: 'split', matched: cand };
      }
      if (brand.length >= BRAND_AFFIX_MIN_LEN &&
          cand.length - brand.length <= BRAND_AFFIX_MAX_EXTRA &&
          affixIsDeceptive_(cand, brand)) {
        return { domain: domain, brandName: brand, match: 'affix', matched: cand };
      }
      if (brand.length >= BRAND_FUZZY_MIN_LEN &&
          !isEnglishExtension_(cand, brand) &&
          editDistance_(cand, brand, BRAND_FUZZY_MAX_DISTANCE) <= BRAND_FUZZY_MAX_DISTANCE) {
        return { domain: domain, brandName: brand, match: 'fuzzy', matched: cand };
      }
    }
  }
  return null;
}

/**
 * Decides whether a candidate that contains a brand does so deceptively.
 *
 * Measured against a sweep of ordinary display names, a plain "contains the
 * brand plus up to 3 characters" rule matched 23 of 55 innocent names — Squares
 * Bakery, Notions Craft Shop, Amazonia Travel, Cloudflared Tunnel, Discounts
 * Weekly. Every one of them was the brand plus an English suffix.
 *
 * So the rule is asymmetric, because the attacks are:
 *  - Extra characters BEFORE the brand are always deceptive. "edocusign" is the
 *    motivating case and there is no ordinary word that prefixes a brand name.
 *  - Extra characters AFTER the brand only count when they contain a digit
 *    ("docusign24"). A purely alphabetic tail is how English forms plurals and
 *    participles, and matching it is how this detector would earn its mute.
 *
 * Brands glued to a suffix across a separator ("docusign-inc") are already
 * caught by the word-boundary pass, so nothing is lost.
 *
 * @param {string} cand
 * @param {string} brand
 * @returns {boolean}
 */
function affixIsDeceptive_(cand, brand) {
  const at = cand.indexOf(brand);
  if (at === -1) return false;
  if (at > 0) return true; // something precedes the brand
  return !isEnglishExtension_(cand, brand);
}

/**
 * True when the candidate is just the brand with an alphabetic tail — how
 * English forms plurals and participles ("cloudflared", "capitalones",
 * "mailchimped"). Both the affix rule and the edit-distance rule have to
 * exclude these or they flag ordinary company names.
 * @param {string} cand
 * @param {string} brand
 * @returns {boolean}
 */
function isEnglishExtension_(cand, brand) {
  if (cand.indexOf(brand) !== 0 || cand.length <= brand.length) return false;
  return /^[a-z]+$/.test(cand.substring(brand.length));
}

/**
 * Splits a normalized display name into brand-comparison candidates: each word,
 * plus each adjacent pair joined. The pairs are what catch separator-split
 * brands ("docu sign", "docu-sign") without squashing the whole string, which
 * would invent brand names across word boundaries.
 * @param {string} normalized
 * @returns {string[]}
 */
function brandCandidates_(normalized) {
  if (!normalized) return [];
  const tokens = normalized.split(/[^a-z0-9]+/).filter(t => t.length >= 3);
  const candidates = tokens.slice();
  for (let i = 0; i + 1 < tokens.length; i++) {
    candidates.push(tokens[i] + tokens[i + 1]);
  }
  return candidates;
}

/**
 * Levenshtein distance, abandoning as soon as it provably exceeds max.
 * @param {string} a
 * @param {string} b
 * @param {number} max
 * @returns {number} The distance, or a value > max if it exceeds max.
 */
function editDistance_(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = [];
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}
