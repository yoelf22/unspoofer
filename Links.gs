/**
 * D5 — link analysis. PARSE ONLY.
 *
 * ============================================================================
 * Nothing in this file may ever fetch a URL. No UrlFetchApp, no exceptions, no
 * config flag that turns it on. A request would originate from the inbox
 * owner's own Google identity and IP, which confirms the address is live and
 * hands the kit a fingerprint of the person investigating it. Many kits cloak
 * on exactly that. Analysis is static, always.
 * ============================================================================
 *
 * Every URL that leaves this file — into a log, an alert email, a debug report —
 * is defanged first.
 */

const D5_WEIGHTS = {
  rootScript: 100,   // hard: unrelated host serving a bare script at web root
  unrelatedToBrand: 30,
  recipientInUrl: 30,
  anchorMismatch: 25,
};

const D5_MAX_LINKS = 50;

/**
 * Root domains whose /url?q= style endpoints are redirectors, not destinations.
 * Google Calendar rewrites every link in an event description through
 * google.com/url, and Calendly wraps user-supplied links through calendly.com/url,
 * so judging the wrapper host answers the wrong question: the anchor text names
 * the real target and the href names the redirector, which is not a mismatch.
 * Unwrapping also strengthens the other rules — an open-redirect lure is then
 * judged on where it actually lands.
 */
const D5_REDIRECT_ROOTS = ['google.com', 'calendly.com', 'outlook.com'];

/**
 * Core CMS and application files that legitimately sit at web root. Without
 * this allowlist the root-script rule fires on every WordPress site on earth.
 */
const D5_ROOT_SCRIPT_ALLOWLIST = [
  'index.php', 'wp-login.php', 'xmlrpc.php', 'wp-cron.php', 'wp-signup.php',
  'admin.php', 'login.php', 'search.php', 'contact.php',
  'unsubscribe.php', 'subscribe.php', 'preferences.php', 'profile.php',
  'default.asp', 'default.aspx', 'index.asp', 'index.aspx',
];

const D5_ROOT_SCRIPT_PATTERN = /^\/([A-Za-z0-9_-]{1,24}\.(?:php|asp|aspx|cgi|pl|jsp))$/i;

/**
 * Renders a URL unclickable for logs and alert emails.
 * @param {string} url
 * @returns {string}
 */
function defang(url) {
  if (!url) return '';
  return url
    .replace(/^https:/i, 'hxxps:')
    .replace(/^http:/i, 'hxxp:')
    .replace(/\./g, '[.]');
}

/**
 * Decodes a message body far enough to find URLs in it.
 *
 * Quoted-printable soft breaks split URLs across lines and =3D hides every
 * query separator, so without this step href extraction silently finds nothing.
 * @param {Object} ctx
 * @returns {string}
 */
function decodeBody_(ctx) {
  let body = ctx.body || '';
  const cte = ctx.header('content-transfer-encoding').toLowerCase();

  // In a multipart message the transfer encoding lives on each part, not on the
  // top-level header, so trusting the header alone leaves the common case
  // undecoded and D5 silently finds nothing. Quoted-printable is unambiguous
  // enough to detect from the body itself, and over-decoding costs nothing when
  // all we take from the body is URLs.
  if (cte.indexOf('quoted-printable') !== -1 || /=3D|=\r?\n/.test(body)) {
    body = body.replace(/=\r?\n/g, '').replace(/=3D/gi, '=');
  }
  if (cte.indexOf('base64') !== -1) {
    try {
      body = Utilities.newBlob(Utilities.base64Decode(body.replace(/\s+/g, ''))).getDataAsString();
    } catch (e) {
      Logger.log('base64 body decode failed: ' + e.message);
    }
  }
  return body;
}

/**
 * Extracts hrefs and their anchor text.
 * @param {string} body
 * @returns {Array<{href: string, text: string}>}
 */
function extractLinks_(body) {
  const links = [];
  if (!body) return links;

  const seen = {};
  const add = function (href, text) {
    const key = href.replace(/[.,;)\]]+$/, '');
    if (seen[key] || links.length >= D5_MAX_LINKS) return;
    seen[key] = true;
    links.push({ href: key, text: text });
  };

  const anchors = /<a\b[^>]*?href\s*=\s*["']?(https?:\/\/[^"'>\s]+)["']?[^>]*>([\s\S]{0,200}?)<\/a>/gi;
  let m;
  while ((m = anchors.exec(body)) !== null) {
    add(m[1], m[2].replace(/<[^>]*>/g, '').trim());
  }

  // Bare URLs, so a text/plain lure is analysed too. Anchors are collected
  // first, so a URL that already appeared as an href keeps its anchor text.
  const bare = /(?:^|[\s<>"'])(https?:\/\/[^\s<>"']+)/gi;
  while ((m = bare.exec(body)) !== null) {
    add(m[1], '');
  }

  return links;
}

/**
 * Pulls the hostname out of a URL without constructing a URL object
 * (Apps Script has no URL global).
 * @param {string} url
 * @returns {string}
 */
function urlHost_(url) {
  const m = url.match(/^https?:\/\/([^\/?#:]+)/i);
  return m ? m[1].toLowerCase() : '';
}

/**
 * Pulls the path (no query, no fragment) out of a URL.
 * @param {string} url
 * @returns {string}
 */
function urlPath_(url) {
  const m = url.match(/^https?:\/\/[^\/?#]*(\/[^?#]*)/i);
  return m ? m[1] : '/';
}

/**
 * Follows redirect wrappers to the URL a click actually lands on.
 * Only hosts on D5_REDIRECT_ROOTS are unwrapped: unwrapping anyone's ?url=
 * param would let a phishing host claim a brand by naming it in a query string.
 * @param {string} url
 * @returns {string}
 */
function unwrapRedirect_(url) {
  for (let i = 0; i < 3; i++) { // wrappers nest — Calendar wraps Calendly wraps the target
    if (D5_REDIRECT_ROOTS.indexOf(extractRootDomain(urlHost_(url))) === -1) break;
    const m = url.match(/[?&](?:q|url)=([^&]+)/i);
    if (!m) break;
    let inner;
    try {
      inner = decodeURIComponent(m[1]);
    } catch (e) {
      break;
    }
    if (!/^https?:\/\//i.test(inner)) break;
    url = inner;
  }
  return url;
}

/**
 * True when the message carries a real calendar invitation.
 *
 * An invite's own links identify the invitee by construction — Google Calendar's
 * eid is base64 of "<event id> <invitee address>" — so the recipient-in-URL rule
 * reads a structural fact as a targeting signal on every meeting invite.
 *
 * ponytail: a phisher can attach an ics to buy back those 30 points. Narrow to
 * invite-host links only if that shows up.
 * @param {Object} ctx
 * @returns {boolean}
 */
function isCalendarInvite_(ctx) {
  const raw = ctx.raw || '';
  return /content-type:\s*text\/calendar/i.test(raw) && /^METHOD:(REQUEST|CANCEL|REPLY)/im.test(raw);
}

/**
 * Analyses the body's links.
 * @param {Object} ctx
 * @param {{displayName: string, email: string}} sender
 * @param {Object|null} brandMatch - Brand identified by D1, if any
 * @returns {Array} Evidence entries (possibly empty)
 */
function checkLinks_(ctx, sender, brandMatch) {
  const out = [];
  const links = extractLinks_(decodeBody_(ctx));
  if (links.length === 0) return out;

  const senderRoot = extractRootDomain(sender.email.split('@')[1] || '');
  // Without a sending domain there is nothing to judge a link's relatedness
  // against, and every rule below would fire on ordinary mail. Under-flag.
  if (!senderRoot) return out;

  // A brand sending its own mail links to its own social profiles, help centre
  // and sibling domains — Zoom's zoom.us notifications link to zoom.com,
  // linkedin.com and youtube.com, all legitimately. "Claims X but links
  // elsewhere" only carries signal when the sender is NOT X; when it is, the
  // rule degenerates into "a brand may only link to itself" and fires on every
  // legitimate brand notification. Drop the brand and let the sender-relative
  // rules (root script, recipient-in-URL, anchor mismatch) do the work.
  let brandRoot = brandMatch ? extractRootDomain(brandMatch.domain) : '';
  if (brandRoot && (brandRoot === senderRoot || isRelatedBrandDomain(brandRoot, senderRoot))) {
    brandRoot = '';
  }
  const recipient = (ctx.header('delivered-to') || ctx.header('to') || '').toLowerCase();

  const invite = isCalendarInvite_(ctx);

  // Root domains of the URLs the message itself declares as its list-manage
  // endpoints. RFC 8058 one-click requires that URL to identify the recipient,
  // and ESPs host it on their own domain (Klaviyo: manage.kmail-lists.com),
  // which is unrelated to the brand that signed the mail. The header is the
  // sender's own declaration, so no ESP allowlist is needed.
  const listRoots = (ctx.header('list-unsubscribe').match(/https?:\/\/[^\s<>,]+/gi) || [])
    .map((u) => extractRootDomain(urlHost_(u)));

  const seen = {};
  for (const link of links) {
    const href = unwrapRedirect_(link.href);
    const host = urlHost_(href);
    if (!host) continue;
    const root = extractRootDomain(host);
    const relatedToSender = root === senderRoot || isRelatedBrandDomain(senderRoot, root);
    const relatedToBrand = brandRoot && (root === brandRoot || isRelatedBrandDomain(brandRoot, root));

    // Bare script at web root on a host unrelated to the sender. This is the
    // two-compromised-hosts pattern: an authorized relay stitched to somebody
    // else's hacked CMS, where the kit lives at a path the real site never uses.
    const pathMatch = urlPath_(href).match(D5_ROOT_SCRIPT_PATTERN);
    if (pathMatch && !relatedToSender &&
        D5_ROOT_SCRIPT_ALLOWLIST.indexOf(pathMatch[1].toLowerCase()) === -1 &&
        !seen.rootScript) {
      seen.rootScript = true;
      out.push(evidence_('D5', D5_WEIGHTS.rootScript,
        'Links to a bare script at the web root of ' + root +
        ', a host unrelated to the sender',
        { details: 'Link: ' + defang(href) }));
    }

    if (brandRoot && !relatedToBrand && !relatedToSender && !seen.unrelated) {
      seen.unrelated = true;
      out.push(evidence_('D5', D5_WEIGHTS.unrelatedToBrand,
        'Message claims ' + brandRoot + ' but links to ' + root +
        ', which belongs to neither the brand nor the sender',
        { details: 'Link: ' + defang(href) }));
    }

    // Only on a host unrelated to the sender. Your address in a link back to
    // the domain that signed the message is that sender addressing you — every
    // bulk mailer puts it in the unsubscribe link, and RFC 8058 one-click
    // requires the link to identify the recipient. The signal the rule is for
    // is a kit on someone else's host pre-filling your address on a login page.
    // A host the List-Unsubscribe header names is that sender's declared
    // list-manage endpoint, not somebody else's host.
    if (recipient && !invite && !seen.recipient && !relatedToSender &&
        listRoots.indexOf(root) === -1 && urlCarriesRecipient_(href, recipient)) {
      seen.recipient = true;
      out.push(evidence_('D5', D5_WEIGHTS.recipientInUrl,
        'Your address is encoded in the link target — the page knows who opened it',
        { details: 'Link: ' + defang(href) }));
    }

    // Anchor text naming a different domain than the link actually goes to.
    // Not on invites: Calendar rewrites every anchor it renders — description
    // links through google.com/url, and a Zoom URL typed into the Location
    // field becomes a google.com/maps/search link — so the text names the
    // real target and the href names Google. That is the rule's exact shape,
    // on every legitimate invite with a meeting link.
    const claimed = link.text.match(/\b([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}\b/i);
    if (claimed && !invite && !seen.anchor) {
      const claimedRoot = extractRootDomain(claimed[0]);
      if (claimedRoot !== root && !isRelatedBrandDomain(claimedRoot, root)) {
        seen.anchor = true;
        out.push(evidence_('D5', D5_WEIGHTS.anchorMismatch,
          'Link text says ' + claimedRoot + ' but the link goes to ' + root,
          { details: 'Link: ' + defang(href) + ' | Text: ' + link.text }));
      }
    }
  }

  return out;
}

/**
 * Checks whether the recipient's address appears in a URL as plaintext, base64,
 * or MD5 — the three ways kits pre-fill the victim's address on a login page.
 * @param {string} url
 * @param {string} recipient
 * @returns {boolean}
 */
function urlCarriesRecipient_(url, recipient) {
  const address = (recipient.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/) || [recipient])[0];
  if (!address || address.indexOf('@') === -1) return false;

  const lower = url.toLowerCase();
  if (lower.indexOf(encodeURIComponent(address).toLowerCase()) !== -1) return true;
  if (lower.indexOf(address) !== -1) return true;

  try {
    const b64 = Utilities.base64Encode(address).replace(/=+$/, '').toLowerCase();
    if (b64 && lower.indexOf(b64) !== -1) return true;
    const md5 = Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, address)
      .map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); })
      .join('');
    if (lower.indexOf(md5) !== -1) return true;
  } catch (e) {
    // Utilities unavailable — plaintext check above still stands.
  }
  return false;
}

/**
 * Defangs every URL inside a block of free text.
 *
 * Applied to anything that reaches a log, an alert email or a debug report —
 * subjects and display names included, since both routinely carry the lure URL.
 * The alert about a phishing message must not itself be a phishing message.
 * @param {string} text
 * @returns {string}
 */
function defangText_(text) {
  if (!text) return '';
  return String(text).replace(/https?:\/\/[^\s<>"']+/gi, function (url) {
    return defang(url);
  });
}
