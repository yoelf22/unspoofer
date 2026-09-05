/**
 * D6 — organizational identity claimed through a consumer freemail address.
 *
 * Some impersonation mail avoids a branded display name entirely. Instead it
 * uses the real person's name as the display name, appends the organization to
 * the local part (person.organization@freemail), then claims affiliation with
 * that organization in the body. That shape is independent of a brand list.
 */

const CONSUMER_FREEMAIL_DOMAINS = [
  'aol.com', 'gmail.com', 'googlemail.com', 'hotmail.com', 'live.com',
  'outlook.com', 'yahoo.com', 'icloud.com', 'me.com', 'proton.me',
  'protonmail.com', 'gmx.com', 'mail.com',
];

/**
 * Finds an organization token appended to the sender's own name in a freemail
 * local part and corroborated by an explicit affiliation claim in the body.
 * Example: Orla King <orlaking.panmacmillan@aol.com> plus "at Pan Macmillan".
 *
 * The sender-name subtraction is the false-positive gate: ordinary personal
 * addresses such as orla.king@aol.com leave no organization token. Requiring
 * an explicit at/from/with/for claim keeps incidental body mentions clean.
 *
 * @param {Object} ctx
 * @param {{displayName: string, email: string}} sender
 * @returns {Array} evidence entries
 */
function checkFreemailIdentityClaim_(ctx, sender) {
  if (!sender.email || !sender.displayName) return [];

  const parts = sender.email.toLowerCase().split('@');
  if (parts.length !== 2) return [];
  const domain = extractRootDomain(parts[1]);
  if (CONSUMER_FREEMAIL_DOMAINS.indexOf(domain) === -1) return [];

  const compact = function (s) {
    return normalizeToAscii(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  };
  const local = compact(parts[0]);
  const person = compact(sender.displayName);
  if (person.length < 5 || local.length <= person.length || local.indexOf(person) !== 0) return [];

  const organization = local.substring(person.length);
  if (organization.length < 6 || organization.length > 40) return [];

  const body = decodeBody_(ctx).toLowerCase();
  if (!body) return [];
  const spacedOrganization = organization.split('').join('[\\s._&-]*');
  const affiliation = new RegExp(
    '\\b(?:at|from|with|for)\\s+(?:the\\s+)?' + spacedOrganization + '\\b',
    'i'
  );
  if (!affiliation.test(body)) return [];

  return [evidence_('D6', 60,
    'Consumer freemail address embeds an organization claimed in the message body',
    {
      brand: organization,
      details: 'Freemail: ' + domain + ' | name token: ' + person +
        ' | appended organization token: ' + organization,
    })];
}
