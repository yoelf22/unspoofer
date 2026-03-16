/**
 * Core spoof-detection logic: parse sender, normalize, compare domains.
 */

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
 * Main spoof-detection check for a single Gmail message.
 * @param {GmailMessage} message
 * @returns {{isSpoof: boolean, reason: string, brand: string, details: string}}
 */
function checkForSpoof(message) {
  const from = message.getFrom();
  const result = { isSpoof: false, reason: '', brand: '', details: '' };

  // 1. Parse sender
  const sender = parseSender(from);
  if (!sender.displayName || !sender.email) return result;

  // 2. Normalize display name and look for brand match
  const normalizedName = normalizeToAscii(sender.displayName);
  const brandMatch = findSpoofedBrand(normalizedName);
  if (!brandMatch) return result;

  // 3. Extract domain from the actual email address
  const emailDomain = sender.email.split('@')[1];
  if (!emailDomain) return result;
  const actualRoot = extractRootDomain(emailDomain);

  // 4. Check if the actual sender domain matches the brand domain
  const brandRoot = extractRootDomain(brandMatch.domain);
  if (actualRoot === brandRoot) return result; // Legit — actual domain matches brand

  // 5. Also extract domain from display name if present, and compare
  const impliedDomain = extractDomainFromDisplayName(sender.displayName);
  if (impliedDomain) {
    const impliedRoot = extractRootDomain(impliedDomain);
    if (impliedRoot === actualRoot) return result; // Display domain matches sender domain — OK
  }

  // 6. Spoof detected
  result.isSpoof = true;
  result.brand = brandMatch.brandName;
  result.reason = 'Display name impersonates ' + brandMatch.domain +
    ' but email is from ' + actualRoot;
  result.details = 'From: ' + from + ' | Normalized: ' + normalizedName +
    ' | Actual domain: ' + actualRoot;

  return result;
}
