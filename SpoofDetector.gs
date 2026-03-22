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
  { platform: 'alibaba cloud', pattern: /(?:header\.s|\bs)=aliyun-[a-z0-9-]*\b/ },
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
 * @param {GmailMessage} message
 * @returns {string|null} The matched platform name or null
 */
function checkSuspiciousDkimSelector(message) {
  try {
    const raw = message.getRawContent();
    Logger.log('  [DKIM debug] raw length=' + raw.length);

    // Only parse headers (everything before the first blank line).
    // Handle both \r\n\r\n (RFC 2822) and \n\n (Gmail normalization).
    let headerEnd = raw.indexOf('\r\n\r\n');
    const lfEnd = raw.indexOf('\n\n');
    Logger.log('  [DKIM debug] CRLF boundary=' + headerEnd + ', LF boundary=' + lfEnd);
    if (headerEnd <= 0) headerEnd = lfEnd;
    if (headerEnd <= 0) {
      Logger.log('  [DKIM debug] No header boundary found');
      return null;
    }
    const headers = raw.substring(0, headerEnd);
    Logger.log('  [DKIM debug] header length=' + headers.length);

    // Log any s= values found in headers for diagnostics
    const selectorMatches = headers.match(/\bs=[a-z0-9-]+/gi);
    Logger.log('  [DKIM debug] s= values found: ' + JSON.stringify(selectorMatches));

    for (const entry of SUSPICIOUS_DKIM_SELECTORS) {
      const matched = entry.pattern.test(headers);
      Logger.log('  [DKIM debug] pattern ' + entry.pattern + ' matched=' + matched);
      if (matched) {
        return entry.platform;
      }
    }
    return null;
  } catch (e) {
    Logger.log('  [DKIM debug] ERROR: ' + e.message);
    return null;
  }
}

/** @type {string[]|null} */
let _whitelistCache = null;

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
 * Main spoof-detection check for a single Gmail message.
 * @param {GmailMessage} message
 * @returns {{isSpoof: boolean, reason: string, brand: string, details: string}}
 */
function checkForSpoof(message) {
  const from = message.getFrom();
  const result = { isSpoof: false, reason: '', brand: '', details: '' };

  // 1. Parse sender
  const sender = parseSender(from);
  if (!sender.email) return result;

  // 2. Check sender whitelist
  if (isSenderWhitelisted(sender.email)) return result;

  // 3. Check if sender is from a suspicious platform (e.g., firebaseapp.com)
  const senderDomain = sender.email.split('@')[1];
  const suspiciousPlatform = isSuspiciousPlatform(senderDomain);
  if (suspiciousPlatform) {
    result.isSpoof = true;
    result.brand = suspiciousPlatform;
    result.reason = 'Sent from suspicious platform: ' + suspiciousPlatform;
    result.details = 'From: ' + from + ' | Platform domain: ' + senderDomain;
    return result;
  }

  // 3b. Check DKIM selector for suspicious platforms using custom domains
  //     (e.g., Firebase with selector "firebase1" on a random domain)
  const dkimPlatform = checkSuspiciousDkimSelector(message);
  if (dkimPlatform) {
    result.isSpoof = true;
    result.brand = dkimPlatform;
    result.reason = 'Sent via suspicious platform: ' + dkimPlatform + ' (custom domain)';
    result.details = 'From: ' + from + ' | Sender domain: ' + senderDomain;
    return result;
  }

  // 4. Normalize display name and look for brand match
  const normalizedName = sender.displayName ? normalizeToAscii(sender.displayName) : '';
  let brandMatch = findSpoofedBrand(normalizedName);

  // 4b. Also check the email local part for brand impersonation
  //     (e.g., domains.notifications.wix.renew@investireinlettonia.it)
  if (!brandMatch) {
    const localPart = sender.email.split('@')[0].replace(/[._+-]/g, ' ');
    brandMatch = findSpoofedBrand(localPart);
  }
  if (!brandMatch) return result;

  // 5. Extract domain from the actual email address
  const emailDomain = senderDomain;
  if (!emailDomain) return result;
  const actualRoot = extractRootDomain(emailDomain);

  // 6. Check if the actual sender domain matches the brand domain
  const brandRoot = extractRootDomain(brandMatch.domain);
  if (actualRoot === brandRoot) return result; // Legit — actual domain matches brand

  // 7. Check if sender is a known related domain for this brand (e.g., YouTube ↔ Google)
  if (isRelatedBrandDomain(brandRoot, actualRoot)) return result;

  // 8. Also extract domain from display name if present, and compare
  const impliedDomain = extractDomainFromDisplayName(sender.displayName);
  if (impliedDomain) {
    const impliedRoot = extractRootDomain(impliedDomain);
    if (impliedRoot === actualRoot) return result; // Display domain matches sender domain — OK
  }

  // 9. Spoof detected
  result.isSpoof = true;
  result.brand = brandMatch.brandName;
  result.reason = 'Display name impersonates ' + brandMatch.domain +
    ' but email is from ' + actualRoot;
  result.details = 'From: ' + from + ' | Normalized: ' + normalizedName +
    ' | Actual domain: ' + actualRoot;

  return result;
}
