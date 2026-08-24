/**
 * D4 — MUA fingerprint consistency.
 *
 * Scored, never hard. Every signal here is individually normal for some
 * legitimate mailer; the combination is what says "assembled by a script, not
 * composed by a person".
 */

const D4_WEIGHTS = {
  htmlOnly: 20,
  noMailer: 10,
  messageIdHost: 10,
  odd_hours: 10,
};

/**
 * Message-ID hosts that belong to a known generator rather than the sending
 * domain. A mismatch against these AND against the From domain is the signal.
 */
const D4_KNOWN_MESSAGE_ID_HOSTS = [
  'mail.gmail.com',
  'google.com',
  'prod.outlook.com',
  'namprd.prod.outlook.com',
  'protection.outlook.com',
  'amazonses.com',
  'sendgrid.net',
  'mailchimp.com',
  'mandrillapp.com',
  'substack.com',
  'postmarkapp.com',
  'sparkpostmail.com',
  'mailgun.org',
];

/** Local hours that read as machine-scheduled rather than human-composed. */
const D4_ODD_HOUR_START = 2;
const D4_ODD_HOUR_END = 5;

/**
 * Scores a message's mailer fingerprint.
 * @param {Object} ctx
 * @param {{displayName: string, email: string}} sender
 * @returns {Array} Evidence entries (possibly empty)
 */
function checkMuaFingerprint_(ctx, sender) {
  const out = [];
  if (!ctx.headerBlock) return out; // headers unavailable — say nothing

  const contentType = ctx.header('content-type').toLowerCase();
  if (contentType.indexOf('text/html') === 0) {
    out.push(evidence_('D4', D4_WEIGHTS.htmlOnly,
      'Top-level Content-Type is text/html with no multipart/alternative — human ' +
      'mail clients emit both parts',
      { details: 'Content-Type: ' + contentType }));
  }

  if (!ctx.header('x-mailer') && !ctx.header('user-agent')) {
    out.push(evidence_('D4', D4_WEIGHTS.noMailer,
      'No X-Mailer and no User-Agent header',
      { details: 'Both mailer-identifying headers absent' }));
  }

  const messageId = ctx.header('message-id');
  const at = messageId.lastIndexOf('@');
  if (at !== -1) {
    const idHost = messageId.substring(at + 1).replace(/>$/, '').toLowerCase();
    const senderRoot = extractRootDomain(sender.email.split('@')[1] || '');
    const known = D4_KNOWN_MESSAGE_ID_HOSTS.some(function (h) {
      return idHost === h || idHost.endsWith('.' + h);
    });
    // A host with no dot is the generator's own internal hostname (SendGrid's
    // geopod-ismtpd-115, Postfix's mail01), not a domain. It can agree with
    // nothing, so it says nothing.
    if (idHost && idHost.indexOf('.') !== -1 && !known &&
        extractRootDomain(idHost) !== senderRoot) {
      out.push(evidence_('D4', D4_WEIGHTS.messageIdHost,
        'Message-ID host ' + idHost + ' matches neither the sending domain nor a ' +
        'known mail generator',
        { details: 'Message-ID: ' + messageId }));
    }
  }

  const odd = oddHourSend_(ctx.header('date'));
  if (odd !== null) {
    out.push(evidence_('D4', D4_WEIGHTS.odd_hours,
      'Composed at ' + odd + ':00 in the sender\'s own stated timezone',
      { details: 'Date: ' + ctx.header('date') }));
  }

  return out;
}

/**
 * Returns the sender's local hour if the Date header says the message was
 * composed in the small hours, otherwise null.
 *
 * The Date header's UTC offset is set by the composing client, so it is the
 * sender's own claimed timezone — no geolocation needed. A +0000 offset is
 * ignored: bulk senders normalize to UTC and would otherwise all look nocturnal.
 *
 * ponytail: uses the claimed offset, not the submission IP's real geography.
 * Wire D3's ASN/geo lookup in here if offset-faking shows up.
 *
 * @param {string} dateHeader
 * @returns {number|null}
 */
function oddHourSend_(dateHeader) {
  if (!dateHeader) return null;
  const m = dateHeader.match(/\b(\d{1,2}):(\d{2}):\d{2}\s*([+-])(\d{2})(\d{2})/);
  if (!m) return null;
  const offsetHours = Number(m[4]);
  const offsetMinutes = Number(m[5]);
  if (offsetHours === 0 && offsetMinutes === 0) return null; // UTC-normalized
  const hour = Number(m[1]);
  return hour >= D4_ODD_HOUR_START && hour <= D4_ODD_HOUR_END ? hour : null;
}
