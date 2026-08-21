/**
 * D3 — Received-chain injection point.
 *
 * The most architecturally invasive detector and the one most likely to flag
 * legitimate mail, so it ships behind a flag, OFF. Turn it on only after the
 * relay allowlist has been exercised against a few days of real inbox traffic.
 *
 * What it looks for: a message submitted INTO a large provider's authorized
 * SMTP relay FROM a host that has nothing to do with the domain in the From
 * header. That is a compromised or rented tenant relay. Every authentication
 * check passes, because the relay really is authorized to send for that
 * domain — SPF, DKIM and DMARC are measuring the wrong thing. This is the
 * "authenticated and anomalous" case in its purest form.
 */

/**
 * D3 is ON.
 *
 * Enabled 2026-08-21 on evidence, not assumption: reportRelayPairs() over 97
 * messages of real inbox+spam found exactly one provider-relay submission, and
 * it was the sabeng.it attack. An independent 25-message Gmail API sample over
 * a 7-day window found none at all. Nothing legitimate in this mailbox enters a
 * provider SMTP relay, so there is nothing for D3 to false-positive on.
 *
 * Re-run reportRelayPairs() if the mix of senders changes.
 */
let ENABLE_RECEIVED_CHAIN = true; // `let` so testDetection() can exercise it

/**
 * Opt-in ASN/geo enrichment of the submission IP.
 *
 * ponytail: NOT IMPLEMENTED, deliberately. Wiring UrlFetchApp into this file
 * makes Apps Script request the script.external_request OAuth scope from every
 * installer, including everyone who leaves this flag off. The offline signals
 * below already catch the case that motivated D3. See README ("Optional IP
 * enrichment") for the two-line addition if you want it — the contract is:
 * send the IP and nothing else, never message content, subject or addresses.
 */
const ENABLE_IP_ENRICHMENT = false;

const D3_WEIGHT = 100;
const RELAY_ALLOWLIST_PROPERTY_KEY = 'relayAllowlist';

/**
 * SMTP relays operated by large providers on behalf of their tenants. A message
 * entering one of these from outside the sending organization is the pattern.
 */
const PROVIDER_RELAYS = [
  'smtp-relay.gmail.com',
  'smtp-relay.google.com',
  'aspmx.l.google.com',
  'smtp.office365.com',
  'protection.outlook.com',
];

/**
 * Sender-domain + relay-host pairs known to be legitimate.
 *
 * Deliberately EMPTY. Newsletters and transactional senders route through
 * provider relays all day, so this list is what stops D3 flagging every one of
 * them — but a guessed entry is worse than no entry, because it permanently
 * exempts a domain+relay pair that an attacker can then use freely. Populate it
 * from your own traffic, not from assumptions:
 *
 *   1. Run reportRelayPairs() — it prints every sender+relay pair currently in
 *      your inbox, marking which ones D3 would flag.
 *   2. For each pair you recognize as legitimate, run
 *      addRelayPair('example.com', 'smtp-relay.gmail.com').
 *   3. Only then set ENABLE_RECEIVED_CHAIN = true.
 *
 * Runtime additions go to Script Properties, so this constant stays empty and
 * the tuning survives a redeploy.
 */
const RELAY_ALLOWLIST = [];

/** @type {string[]|null} */
let _relayAllowlistCache = null;

/**
 * Returns the relay allowlist: the built-in pairs plus any added at runtime.
 * @returns {string[]}
 */
function getRelayAllowlist_() {
  if (_relayAllowlistCache !== null) return _relayAllowlistCache;
  let extra = [];
  try {
    const raw = PropertiesService.getScriptProperties()
      .getProperty(RELAY_ALLOWLIST_PROPERTY_KEY);
    extra = raw ? JSON.parse(raw) : [];
  } catch (e) {
    extra = [];
  }
  _relayAllowlistCache = RELAY_ALLOWLIST.concat(extra);
  return _relayAllowlistCache;
}

/**
 * Parses one Received header into the fields D3 needs.
 * @param {string} received
 * @returns {{from: string, ip: string, by: string}}
 */
function parseReceivedHop_(received) {
  const fromMatch = received.match(/\bfrom\s+([^\s;()]+)/i);
  const byMatch = received.match(/\bby\s+([^\s;()]+)/i);
  const ipMatch = received.match(/\[((?:\d{1,3}\.){3}\d{1,3})\]/);
  return {
    from: fromMatch ? fromMatch[1].toLowerCase() : '',
    ip: ipMatch ? ipMatch[1] : '',
    by: byMatch ? byMatch[1].toLowerCase() : '',
  };
}

/**
 * Finds the submission hop — the earliest Received header, which is the last
 * one in the file. Received headers are prepended by each host, so the chain
 * reads newest-first top-down and the bottom entry is where the message
 * entered.
 * @param {Object} ctx
 * @returns {{from: string, ip: string, by: string}|null}
 */
function findSubmissionHop_(ctx) {
  const received = ctx.all('received');
  if (received.length === 0) return null;
  return parseReceivedHop_(received[received.length - 1]);
}

/**
 * Checks whether a host is one of the provider relays.
 * @param {string} host
 * @returns {string} The matched relay, or ''
 */
function matchProviderRelay_(host) {
  if (!host) return '';
  for (const relay of PROVIDER_RELAYS) {
    if (host === relay || host.endsWith('.' + relay)) return relay;
  }
  return '';
}

/**
 * D3 proper.
 *
 * Without DNS (Apps Script has no resolver) SPF ranges cannot be checked
 * directly, so the offline proxy is the HELO name: a host submitting to a
 * provider relay on behalf of example.com normally announces itself under
 * example.com. A HELO root domain that disagrees with the From domain, on a
 * message entering a provider relay, is the injection point.
 *
 * ponytail: HELO-vs-From instead of a real SPF range check. Upgrade path is an
 * SPF lookup, which needs DNS — i.e. the enrichment flag above, or a cached
 * SPF map in Script Properties.
 *
 * @param {Object} ctx
 * @param {{displayName: string, email: string}} sender
 * @returns {Array} Evidence entries (possibly empty)
 */
function checkReceivedChain_(ctx, sender) {
  const out = [];
  if (!ENABLE_RECEIVED_CHAIN) return out;

  const hop = findSubmissionHop_(ctx);
  if (!hop) return out;

  const relay = matchProviderRelay_(hop.by);
  if (!relay) return out;

  const senderRoot = extractRootDomain(sender.email.split('@')[1] || '');
  if (!senderRoot) return out;

  if (getRelayAllowlist_().indexOf(senderRoot + '|' + relay) !== -1) return out;

  const heloRoot = hop.from ? extractRootDomain(hop.from) : '';
  // No HELO name, or a HELO that belongs to the sending domain: ordinary.
  if (!heloRoot || heloRoot === senderRoot || isRelatedBrandDomain(senderRoot, heloRoot)) {
    return out;
  }
  // A bare IP literal as HELO tells us nothing either way.
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(heloRoot)) return out;

  out.push(evidence_('D3', D3_WEIGHT,
    'Submitted into ' + relay + ' from ' + heloRoot +
    ', which is unrelated to the sending domain ' + senderRoot +
    (ctx.auth.allPass ? ' — and SPF, DKIM and DMARC all passed' : ''),
    {
      details: 'Submission hop: from ' + hop.from + (hop.ip ? ' [' + hop.ip + ']' : '') +
        ' by ' + hop.by + ' | From domain: ' + senderRoot +
        ' | auth: spf=' + ctx.auth.spf + ' dkim=' + ctx.auth.dkim +
        ' dmarc=' + ctx.auth.dmarc,
    }));
  return out;
}

/**
 * Adds a legitimate sender-domain + relay pair to the allowlist.
 * Run from the script editor: addRelayPair('substack.com', 'smtp-relay.gmail.com')
 * @param {string} senderRoot
 * @param {string} relayHost
 */
function addRelayPair(senderRoot, relayHost) {
  if (!senderRoot || !relayHost) {
    Logger.log('Usage: addRelayPair("substack.com", "smtp-relay.gmail.com")');
    return;
  }
  const entry = senderRoot.trim().toLowerCase() + '|' + relayHost.trim().toLowerCase();
  const props = PropertiesService.getScriptProperties();
  let extra = [];
  try {
    const raw = props.getProperty(RELAY_ALLOWLIST_PROPERTY_KEY);
    extra = raw ? JSON.parse(raw) : [];
  } catch (e) {
    extra = [];
  }
  if (RELAY_ALLOWLIST.indexOf(entry) !== -1 || extra.indexOf(entry) !== -1) {
    Logger.log('Already allowlisted: ' + entry);
    return;
  }
  extra.push(entry);
  props.setProperty(RELAY_ALLOWLIST_PROPERTY_KEY, JSON.stringify(extra));
  _relayAllowlistCache = null;
  Logger.log('Allowlisted relay pair: ' + entry);
}

/**
 * Prints every sender-domain + relay-host pair in recent mail, so the allowlist
 * can be built from what actually arrives rather than from guesswork.
 *
 * Read-only: labels nothing, sends nothing, changes nothing. Run it before
 * enabling D3, then addRelayPair() the ones you recognize.
 */
function reportRelayPairs() {
  const threads = GmailApp.search(SCAN_QUERY, 0, 100);
  const pairs = {};
  let scanned = 0;

  for (const thread of threads) {
    for (const message of thread.getMessages()) {
      scanned++;
      const ctx = buildMessageContext_(message);
      const hop = findSubmissionHop_(ctx);
      if (!hop) continue;
      const relay = matchProviderRelay_(hop.by);
      if (!relay) continue;

      const sender = parseSender(ctx.from);
      const senderRoot = extractRootDomain(sender.email.split('@')[1] || '');
      if (!senderRoot) continue;

      const key = senderRoot + '|' + relay;
      if (!pairs[key]) pairs[key] = { count: 0, helo: hop.from, allowed: false };
      pairs[key].count++;
      pairs[key].allowed = getRelayAllowlist_().indexOf(key) !== -1;
    }
  }

  const keys = Object.keys(pairs).sort();
  Logger.log('Scanned ' + scanned + ' messages; ' + keys.length +
    ' sender/relay pair(s) entered a provider relay.');
  if (keys.length === 0) {
    Logger.log('Nothing to allowlist — D3 would flag nothing in this window.');
    return;
  }
  for (const key of keys) {
    const p = pairs[key];
    const parts = key.split('|');
    const heloRoot = p.helo ? extractRootDomain(p.helo) : '';
    const wouldFlag = !p.allowed && heloRoot && heloRoot !== parts[0];
    // Deliberately does NOT print a ready-to-paste addRelayPair() call for a
    // flagged pair. A flagged pair is as likely to be the attack as it is to be
    // a newsletter — the first run of this function flagged exactly one pair
    // and it was the phish. Handing over the command to permanently allowlist
    // it would be handing over the command to disarm the detector.
    Logger.log('  ' + key + '  x' + p.count + '  helo=' + (p.helo || '?') +
      (p.allowed ? '  [already allowlisted]'
                 : (wouldFlag ? '  [D3 WOULD FLAG — review this sender. If you ' +
                                'recognize it as legitimate, allowlist it with ' +
                                'addRelayPair(); if you do not, leave it flagged.]'
                              : '  [would not flag]')));
  }
}
