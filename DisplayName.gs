/**
 * D2 — display-name obfuscation.
 *
 * These are scored signals, never hard fails. A display name being ugly is not
 * evidence of a spoof on its own; it is evidence that the name was built to be
 * truncated, and it matters in combination with anything else.
 *
 * The attack these describe: a mobile client shows the first ~30 characters of
 * the display name and nothing else. The real address never renders, so the
 * name is padded with directory-looking noise until it is the only thing the
 * reader sees.
 */

const D2_MAX_PLAUSIBLE_LENGTH = 60;

const D2_WEIGHTS = {
  length: 20,
  pseudoDirectory: 20,
  embeddedAddress: 20,
  identifierRun: 15,
};

/**
 * Pseudo-directory syntax: uppercase key=value pairs of the kind that appear in
 * X.500 / Exchange distinguished names, used decoratively.
 *
 * A genuine legacyExchangeDN starts with "/o=" or "/O=" and is a well-formed
 * chain, so names beginning that way are exempt.
 */
const D2_PSEUDO_DIRECTORY = /(^|[\/|\s])[A-Z]{1,5}=[A-Z0-9]/;
const D2_GENUINE_DN_PREFIX = /^\/o=/i;

/** Long opaque identifier runs — hex envelope ids and similar. */
const D2_IDENTIFIER_RUN = /\b(?:[A-F0-9]{12,}|[A-Z0-9]{14,})\b/;

/**
 * Scores a display name for obfuscation.
 * @param {{displayName: string, email: string}} sender
 * @returns {Array} Evidence entries (possibly empty)
 */
function checkDisplayNameObfuscation_(sender) {
  const out = [];
  const name = sender.displayName;
  if (!name) return out;

  if (name.length > D2_MAX_PLAUSIBLE_LENGTH) {
    out.push(evidence_('D2', D2_WEIGHTS.length,
      'Display name is ' + name.length + ' characters — the real address will not ' +
      'render on a phone',
      { details: 'Display name length: ' + name.length }));
  }

  if (!D2_GENUINE_DN_PREFIX.test(name) && D2_PSEUDO_DIRECTORY.test(name)) {
    out.push(evidence_('D2', D2_WEIGHTS.pseudoDirectory,
      'Display name uses directory-style syntax (X=Y) outside a directory context',
      { details: 'Pseudo-directory tokens in: ' + name }));
  }

  // An address embedded in the display name only matters when it is a different
  // domain from the one actually sending. "billing@acme.com" <no-reply@acme.com>
  // is ordinary transactional mail and must not score.
  const embedded = name.match(/[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/);
  if (embedded) {
    const senderDomain = sender.email.split('@')[1] || '';
    const embeddedRoot = extractRootDomain(embedded[1]);
    if (embeddedRoot && embeddedRoot !== extractRootDomain(senderDomain)) {
      out.push(evidence_('D2', D2_WEIGHTS.embeddedAddress,
        'Display name embeds an address at ' + embeddedRoot +
        ' but the message is from ' + (senderDomain || 'an unknown domain'),
        { details: 'Embedded address: ' + embedded[0] }));
    }
  }

  if (D2_IDENTIFIER_RUN.test(name)) {
    out.push(evidence_('D2', D2_WEIGHTS.identifierRun,
      'Display name contains a long opaque identifier posing as an envelope id',
      { details: 'Identifier run in: ' + name }));
  }

  return out;
}
