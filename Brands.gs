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
  'walla.co.il', 'ynet.co.il',

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
];

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
      return { domain: domain, brandName: extractBrandName(domain) };
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
        return { domain: domain, brandName: brand };
      }
    }
  }

  return null;
}
