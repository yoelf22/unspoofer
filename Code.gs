/**
 * Unspoofer — Gmail display-name spoof detector.
 * Entry points: setup(), scanInbox(), uninstall(), testDetection()
 */

/**
 * Severity labels.
 *
 * Severity is carried by the numeric prefix and the word, never by colour: the
 * maintainer is red/green colourblind, so hue is not allowed to be the signal.
 * Gmail label colours are deliberately not set at all — GmailApp cannot set
 * them without pulling in the Gmail advanced service, and the naming already
 * sorts and communicates the tier.
 *
 * v1's single SPOOF-ALERT label is no longer applied. It is left alone in
 * Gmail so previously flagged mail stays findable.
 */
const SEVERITY_LABELS = {
  CRITICAL: 'SPOOF-1-CRITICAL',
  HIGH: 'SPOOF-2-HIGH',
  WATCH: 'SPOOF-3-WATCH',
};
const SCAN_QUERY = '{in:inbox in:spam} newer_than:3d';
const EXECUTION_TIME_LIMIT_MS = 5 * 60 * 1000; // 5 minutes (safety margin under 6-min limit)

/**
 * Creates the severity labels (idempotent) and sets up the 10-minute trigger.
 */
function setup() {
  // Create the severity labels if they don't exist
  for (const severity in SEVERITY_LABELS) {
    const name = SEVERITY_LABELS[severity];
    if (!GmailApp.getUserLabelByName(name)) {
      GmailApp.createLabel(name);
      Logger.log('Created label: ' + name);
    } else {
      Logger.log('Label already exists: ' + name);
    }
  }

  // Remove existing triggers for scanInbox to avoid duplicates
  const triggers = ScriptApp.getProjectTriggers();
  for (const trigger of triggers) {
    if (trigger.getHandlerFunction() === 'scanInbox') {
      ScriptApp.deleteTrigger(trigger);
      Logger.log('Removed existing scanInbox trigger');
    }
  }

  // Create a new 10-minute trigger
  ScriptApp.newTrigger('scanInbox')
    .timeBased()
    .everyMinutes(10)
    .create();
  Logger.log('Created 10-minute trigger for scanInbox');

  Logger.log('Setup complete. Unspoofer is active.');
}

/**
 * Main scan function — called by trigger every 10 minutes.
 * Searches recent inbox messages, detects spoofs, applies label + star.
 */
function scanInbox() {
  const startTime = Date.now();
  const labels = {};
  for (const severity in SEVERITY_LABELS) {
    labels[severity] = GmailApp.getUserLabelByName(SEVERITY_LABELS[severity]);
  }
  if (!labels.CRITICAL || !labels.HIGH || !labels.WATCH) {
    Logger.log('Severity labels not found. Run setup() first.');
    return;
  }

  let spoofCount = 0;
  let scannedCount = 0;
  let skippedCount = 0;
  const spoofDetails = []; // Collect for email summary

  try {
    const threads = GmailApp.search(SCAN_QUERY, 0, 100);

    for (const thread of threads) {
      // Check execution time
      if (Date.now() - startTime > EXECUTION_TIME_LIMIT_MS) {
        Logger.log('Approaching time limit — stopping scan early.');
        break;
      }

      const messages = thread.getMessages();

      for (const message of messages) {
        // v2 reads each message's raw content, which is the slow call in a
        // scan, so the time guard has to run per message and not only per
        // thread. Whatever is missed stays uncached and is picked up next run.
        if (Date.now() - startTime > EXECUTION_TIME_LIMIT_MS) {
          Logger.log('Approaching time limit — stopping scan early.');
          break;
        }

        const msgId = message.getId();

        // Skip already-processed messages
        if (isProcessed(msgId)) {
          skippedCount++;
          continue;
        }

        scannedCount++;
        const result = checkForSpoof(message);

        if (result.isSpoof) {
          // Label the thread by severity and star the specific message.
          // Never trash, never move, never reply — label and star only.
          const label = labels[result.severity] || labels.WATCH;
          thread.addLabel(label);
          message.star();

          const sender = parseSender(message.getFrom());
          spoofDetails.push({
            subject: message.getSubject(),
            email: sender.email,
            displayName: sender.displayName,
            severity: result.severity,
            score: result.score,
            evidence: result.evidence,
          });

          spoofCount++;
          Logger.log('SPOOF DETECTED [' + result.severity + ' ' + result.score + ']: ' +
            defangText_(result.reason));
          Logger.log('  Details: ' + defangText_(result.details));
        }

        markProcessed(msgId);
      }
    }
  } finally {
    // Always flush cache, even if we hit an error
    flushCache();
  }

  // Send email summary if spoofs were found
  if (spoofDetails.length > 0) {
    sendSpoofAlert_(spoofDetails);
  }

  Logger.log('Scan complete. Scanned: ' + scannedCount +
    ', Skipped (cached): ' + skippedCount +
    ', Spoofs found: ' + spoofCount);
}

/**
 * Gets the current user's email address reliably across Workspace and consumer accounts.
 * @returns {string}
 */
function getOwnerEmail_() {
  return Session.getEffectiveUser().getEmail() ||
    Session.getActiveUser().getEmail() ||
    '';
}

/**
 * Sends an email alert summarizing detected spoofs.
 *
 * Every row carries its full evidence list. A bare verdict is not actionable —
 * the reasoning chain is what lets you tell a real catch from a false positive,
 * and it is what tells you which detector to tune when it is wrong.
 *
 * Severity is shown as a numbered word, never as a colour. All URLs anywhere in
 * this mail are defanged, including any that appear in subjects and display
 * names: an alert about a phishing message must not be one.
 *
 * @param {Array<{subject: string, email: string, displayName: string, severity: string, score: number, evidence: Array}>} spoofs
 */
function sendSpoofAlert_(spoofs) {
  const recipient = getOwnerEmail_();
  if (!recipient) {
    Logger.log('Could not determine owner email — skipping alert');
    return;
  }

  const esc = function (str) {
    return defangText_(str || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  };
  const cell = 'padding:8px;border:1px solid #ddd;vertical-align:top';

  const rows = spoofs.map(function (s) {
    const evidence = (s.evidence || []).map(function (e) {
      return '<li><strong>' + esc(e.detector) + '</strong> (' + e.weight + ') — ' +
        esc(e.note) + '</li>';
    }).join('');
    return '<tr>' +
      '<td style="' + cell + ';white-space:nowrap"><strong>' +
        esc(severityTag_(s.severity)) + '</strong><br><span style="color:#666">score ' +
        s.score + '</span></td>' +
      '<td style="' + cell + '">' + esc(s.subject) + '</td>' +
      '<td style="' + cell + '">' + esc(s.displayName) + '<br>' +
        '<span style="color:#666">' + esc(s.email) + '</span></td>' +
      '<td style="' + cell + '"><ul style="margin:0;padding-left:18px">' + evidence + '</ul></td>' +
      '</tr>';
  }).join('');

  const html = '<h2>Unspoofer: ' + spoofs.length + ' suspicious message' +
    (spoofs.length > 1 ? 's' : '') + '</h2>' +
    '<table style="border-collapse:collapse;width:100%;font-family:sans-serif;font-size:14px">' +
    '<tr style="background:#37474f;color:white">' +
    '<th style="' + cell + ';text-align:left">Severity</th>' +
    '<th style="' + cell + ';text-align:left">Subject</th>' +
    '<th style="' + cell + ';text-align:left">Sender</th>' +
    '<th style="' + cell + ';text-align:left">Evidence</th>' +
    '</tr>' + rows + '</table>' +
    '<p style="color:#666;font-size:12px">Labeled and starred in your inbox. ' +
    'Nothing was moved, trashed or replied to. Links above are defanged — ' +
    'hxxps:// and [.] — do not re-fang and open them.</p>';

  GmailApp.sendEmail(recipient,
    'Unspoofer: ' + spoofs.length + ' suspicious message' +
      (spoofs.length > 1 ? 's' : '') + ' (' + topSeverity_(spoofs) + ')',
    '', { htmlBody: html });
  Logger.log('Alert email sent to ' + recipient);
}

/**
 * Renders a severity as its label name, so the alert and the Gmail label read
 * identically and neither depends on colour.
 * @param {string} severity
 * @returns {string}
 */
function severityTag_(severity) {
  return SEVERITY_LABELS[severity] || SEVERITY_LABELS.WATCH;
}

/**
 * The most severe tier present, for the subject line.
 * @param {Array<{severity: string}>} spoofs
 * @returns {string}
 */
function topSeverity_(spoofs) {
  const order = ['CRITICAL', 'HIGH', 'WATCH'];
  for (const tier of order) {
    for (const s of spoofs) {
      if (s.severity === tier) return severityTag_(tier);
    }
  }
  return severityTag_('WATCH');
}

/**
 * Removes all triggers and clears the processed-message cache.
 */
function uninstall() {
  // Remove all triggers for this project
  const triggers = ScriptApp.getProjectTriggers();
  for (const trigger of triggers) {
    ScriptApp.deleteTrigger(trigger);
  }
  Logger.log('Removed all triggers');

  // Clear cache
  clearProcessedCache();
  Logger.log('Cleared processed message cache');

  Logger.log('Uninstall complete. The severity labels are preserved for review.');
}

/**
 * Adds a sender domain or email address to the whitelist.
 * Run from the script editor: addToWhitelist('example.com')
 * @param {string} domainOrEmail - e.g., "workspace.studio" or "noreply@alerts.example.com"
 */
function addToWhitelist(domainOrEmail) {
  if (!domainOrEmail) {
    Logger.log('Usage: addToWhitelist("domain.com") or addToWhitelist("user@domain.com")');
    return;
  }
  const entry = domainOrEmail.trim().toLowerCase();
  const whitelist = getWhitelist_();
  if (whitelist.includes(entry)) {
    Logger.log('Already whitelisted: ' + entry);
    return;
  }
  whitelist.push(entry);
  PropertiesService.getScriptProperties().setProperty(
    WHITELIST_PROPERTY_KEY, JSON.stringify(whitelist)
  );
  Logger.log('Added to whitelist: ' + entry);
}

/**
 * Removes a sender domain or email address from the whitelist.
 * @param {string} domainOrEmail
 */
function removeFromWhitelist(domainOrEmail) {
  if (!domainOrEmail) return;
  const entry = domainOrEmail.trim().toLowerCase();
  const whitelist = getWhitelist_();
  const idx = whitelist.indexOf(entry);
  if (idx === -1) {
    Logger.log('Not in whitelist: ' + entry);
    return;
  }
  whitelist.splice(idx, 1);
  PropertiesService.getScriptProperties().setProperty(
    WHITELIST_PROPERTY_KEY, JSON.stringify(whitelist)
  );
  Logger.log('Removed from whitelist: ' + entry);
}

/**
 * Shows the current sender whitelist in the log.
 */
function showWhitelist() {
  const whitelist = getWhitelist_();
  if (whitelist.length === 0) {
    Logger.log('Whitelist is empty. Use addToWhitelist("domain.com") to add entries.');
    return;
  }
  Logger.log('Sender whitelist (' + whitelist.length + ' entries):');
  for (const entry of whitelist) {
    Logger.log('  - ' + entry);
  }
}

/**
 * Test function with hard-coded spoof examples.
 * Run from the script editor to verify detection logic.
 */
function testDetection() {
  const testCases = [
    {
      name: 'Cyrillic Wix spoof',
      from: '"W\u0456x.c\u043Em" <info@bistro-pub.de>',
      expectSpoof: true,
    },
    {
      name: 'Cyrillic PayPal spoof',
      from: '"P\u0430yP\u0430l Security" <alerts@some-random.com>',
      expectSpoof: true,
    },
    {
      name: 'Legitimate Wix email',
      from: '"Wix.com" <noreply@wix.com>',
      expectSpoof: false,
    },
    {
      name: 'Legitimate Google email',
      from: '"Google" <no-reply@accounts.google.com>',
      expectSpoof: false,
    },
    {
      name: 'Fullwidth Apple spoof',
      from: '"\uFF21\uFF50\uFF50\uFF4C\uFF45 Support" <help@totally-legit.xyz>',
      expectSpoof: true,
    },
    {
      name: 'Greek omicron Netflix spoof',
      from: '"Netfli\u03BF.com" <billing@fake-stream.net>',
      // Homoglyph "netflio" doesn't match the "netflix" brand, but the generic
      // domain-in-display-name check flags "netflio.com" vs sender fake-stream.net.
      expectSpoof: true,
    },
    {
      name: 'Regular non-brand email',
      from: '"John Smith" <john@example.com>',
      expectSpoof: false,
    },
    {
      name: 'Cyrillic Microsoft spoof',
      from: '"Micr\u043Es\u043Eft.com" <security@phish-domain.ru>',
      expectSpoof: true,
    },
    {
      name: 'Brand subdomain — legitimate',
      from: '"Amazon.com" <ship-confirm@ship.amazon.com>',
      expectSpoof: false,
    },
    {
      name: 'Google display name from YouTube — related domain',
      from: '"Google" <noreply@youtube.com>',
      expectSpoof: false,
    },
    {
      name: 'Microsoft display name from Outlook — related domain',
      from: '"Microsoft Account" <noreply@outlook.com>',
      expectSpoof: false,
    },
    {
      name: 'Meta display name from Instagram — related domain',
      from: '"Meta" <security@instagram.com>',
      expectSpoof: false,
    },
    {
      name: 'Google Search Console — legitimate',
      from: '"Google Search Console" <sc-noreply@google.com>',
      expectSpoof: false,
    },
    {
      name: 'Firebase phishing — suspicious platform',
      from: '"Account Alert" <noreply@kriyiasahbi.firebaseapp.com>',
      expectSpoof: true,
    },
    {
      name: 'Firebase phishing — custom domain with firebase1 DKIM selector',
      from: '"Account Update" <noreply@qgui777com.com>',
      expectSpoof: true,
      rawHeaders: 'DKIM-Signature: v=1; a=rsa-sha256; d=qgui777com.com; s=firebase1; b=abc\n' +
        'Authentication-Results: mx.google.com; dkim=pass header.i=@qgui777com.com header.s=firebase1\n' +
        '\n',
    },
    {
      name: 'Alibaba Cloud mail — legitimate email service, not flagged',
      from: '"Important Notice" <noreply@fa-netscher.de>',
      expectSpoof: false,
      rawHeaders: 'DKIM-Signature: v=1; a=rsa-sha256; d=fa-netscher.de; s=aliyun-ap-southeast-1; b=abc\n' +
        'Authentication-Results: mx.google.com; dkim=pass header.i=@fa-netscher.de header.s=aliyun-ap-southeast-1\n' +
        '\n',
    },
    {
      name: 'Brand in email local part — Wix impersonation',
      from: '"Wix Domain Registration" <domains.notifications.wix.renew@investireinlettonia.it>',
      expectSpoof: true,
    },
    {
      name: 'Legitimate email with brand in local part should not flag',
      from: '"John" <wix-user@wix.com>',
      expectSpoof: false,
    },
    // Generic domain-in-display-name checks (no brand list needed)
    {
      name: 'Generic: display name contains unknown domain, sender mismatch',
      from: '"Support - coolstartup.com" <noreply@totally-unrelated.de>',
      expectSpoof: true,
    },
    {
      name: 'Generic: display name domain matches sender — legitimate',
      from: '"coolstartup.com Updates" <noreply@coolstartup.com>',
      expectSpoof: false,
    },
    {
      name: 'Generic: display name domain matches sender subdomain — legitimate',
      from: '"coolstartup.com" <noreply@mail.coolstartup.com>',
      expectSpoof: false,
    },
    {
      name: 'Generic: no domain in display name — not flagged',
      from: '"Some Random Sender" <hello@whatever.com>',
      expectSpoof: false,
    },
    {
      name: 'ChatGPT spoof from unrelated domain (brand list)',
      from: '"ChatGPT" <noreply@info.casadelsilencio.de>',
      expectSpoof: true,
    },
    {
      name: 'Legitimate OpenAI email',
      from: '"OpenAI" <noreply@openai.com>',
      expectSpoof: false,
    },
    {
      name: 'D6: named editor appends claimed publisher to an AOL address',
      from: '"Orla King" <orlaking.panmacmillan@aol.com>',
      expectSpoof: true,
      expectDetectors: ['D6'],
      raw: [
        'From: "Orla King" <orlaking.panmacmillan@aol.com>',
        'To: author@example.com',
        'Subject: Tangibles',
        'Message-ID: <publisher-outreach@aol.com>',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'I recently spent some time with Tangibles: How Software Turns Hardware into Platforms.',
        'I am a Senior Editor at Pan Macmillan.',
        'Are you working on anything new, and are you represented by a literary agent?',
        '',
        'Best,',
        'Orla King',
        'Senior Editor',
        'Pan Macmillan',
      ].join('\n'),
    },
    {
      name: 'D6 negative: ordinary personal AOL address leaves no organization token',
      from: '"Orla King" <orla.king@aol.com>',
      expectSpoof: false,
      expectNoDetectors: ['D6'],
      raw: 'From: "Orla King" <orla.king@aol.com>\n\nI am an editor at Pan Macmillan.',
    },
    {
      name: 'D6 negative: appended newsletter label without an affiliation claim',
      from: '"Orla King" <orlaking.newsletter@aol.com>',
      expectSpoof: false,
      expectNoDetectors: ['D6'],
      raw: 'From: "Orla King" <orlaking.newsletter@aol.com>\n\nThis is my newsletter about publishing.',
    },
    {
      name: 'D6 negative: organization-like address on its own domain is not freemail',
      from: '"Orla King" <orlaking.panmacmillan@panmacmillan.com>',
      expectSpoof: false,
      expectNoDetectors: ['D6'],
      raw: 'From: "Orla King" <orlaking.panmacmillan@panmacmillan.com>\n\nI am an editor at Pan Macmillan.',
    },
    {
      name: 'Legitimate Gett multi-TLD display name (.business is a gTLD)',
      from: '"Gett.Business" <noreply@business-news.gett.com>',
      expectSpoof: false,
    },
    {
      name: 'Form-service notification: display name = recipient own domain',
      from: '"theroadtlv.com" <formresponses@netlify.com>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
    },
    {
      name: 'Form-service notification still flagged when not your own domain',
      from: '"someoneelse.com" <formresponses@netlify.com>',
      expectSpoof: true,
      ownerDomain: 'theroadtlv.com',
    },
    {
      name: 'Owner impersonation: @-styled bare owner label from external sender',
      from: '"Docs@theroadtlv" <documents@asecureltd.com>',
      expectSpoof: true,
      ownerDomain: 'theroadtlv.com',
    },
    {
      name: 'Owner impersonation: full owner domain from external sender',
      from: '"theroadtlv.com" <documents@asecureltd.com>',
      expectSpoof: true,
      ownerDomain: 'theroadtlv.com',
    },
    {
      name: 'Owner impersonation: @-styled owner domain with TLD from external sender',
      from: '"Docs@theroadtlv.com" <documents@asecureltd.com>',
      expectSpoof: true,
      ownerDomain: 'theroadtlv.com',
    },
    {
      name: 'Owner impersonation: homoglyph in owner token (Cyrillic o) from external sender',
      from: '"Docs@therоadtlv" <documents@asecureltd.com>',
      expectSpoof: true,
      ownerDomain: 'theroadtlv.com',
    },
    // --- D1: affix and near-miss brand matching ---
    {
      name: 'D1: eDocuSign glued prefix (sabeng.it fixture, From only)',
      from: '"eDocuSign Signature | (JFKUSES23SPDLT)/EN=RECIPIENTS/LAN=B7A707497B564FD-29431" <office@sabeng.it>',
      expectSpoof: true,
    },
    {
      name: 'D1: separator-split brand — Docu-Sign',
      from: '"Docu-Sign Envelope" <no-reply@mail-delivery.top>',
      expectSpoof: true,
    },
    {
      name: 'D1: brand with a numeric glued suffix — docusign24',
      from: '"DocuSign24 Notifications" <alerts@random-host.biz>',
      expectSpoof: true,
    },
    {
      name: 'D1 negative: brand plus an English suffix is an ordinary company name',
      from: '"Squares Bakery" <hello@squaresbakery.example>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: "Cloudflared Tunnel" is not a Cloudflare typo-squat',
      from: '"Cloudflared Tunnel" <ops@tunnelco.example>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: "Amazonia Travel" is not Amazon',
      from: '"Amazonia Travel" <trips@amazonia-travel.example>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: "Capitalones Bank" is not Capital One',
      from: '"Capitalones Bank" <info@capitalones.example>',
      expectSpoof: false,
    },
    {
      name: 'D1: typo-squat within edit distance 2 — micosoft',
      from: '"Micosoft Account Team" <security@notms.info>',
      expectSpoof: true,
    },
    {
      name: 'D1 negative: legitimate DocuSign envelope',
      from: '"DocuSign NA3 System" <dse_na3@docusign.net>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: "Notice" must not fuzzy-match notion.so',
      from: '"Important Notice" <billing@fa-netscher.de>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: "Groups" must not affix-match ups.com',
      from: '"Google Groups Digest" <noreply@google.com>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: "Metal" must not affix-match meta.com',
      from: '"Metal Works Ltd" <sales@metalworks.co.il>',
      expectSpoof: false,
    },
    {
      name: 'D1 negative: ordinary long words stay clean',
      from: '"Subscription Recipients Department" <hello@somecompany.example>',
      expectSpoof: false,
    },
    {
      name: 'Owner label from the owner\'s own domain — legitimate internal sender',
      from: '"theroadtlv Team" <admin@theroadtlv.com>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
    },

    // ========================================================================
    // Fixture #1 — the message that motivated v2.
    //
    // Received 2026-08-20. Headers sanitized (recipient address replaced), the
    // routing left intact. SAB S.r.l. (sabeng.it) is a real engineering firm in
    // Perugia whose Google Workspace relay was being abused from an external
    // host; celiacosaraucania.cl is a real Chilean nonprofit whose WordPress
    // install was serving a DocuSign-lure kit at a non-core PHP path. Two
    // legitimate, unrelated hosts stitched into one delivery chain.
    //
    // SPF, DKIM and DMARC all pass, correctly. v1 cleared it on every check.
    // It must be caught by D1, D3, D4 and D5 independently — no single
    // detector may be load-bearing.
    // ========================================================================
    {
      name: 'Fixture #1: eDocuSign via compromised Workspace relay (sabeng.it)',
      from: '"eDocuSign Signature | (JFKUSES23SPDLT)/EN=RECIPIENTS/LAN=B7A707497B564FD-29431" <office@sabeng.it>',
      expectSpoof: true,
      enableReceivedChain: true,
      expectDetectors: ['D1', 'D2', 'D3', 'D4', 'D5'],
      raw: [
        'Return-Path: <office@sabeng.it>',
        'Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])',
        '        by mx.google.com with SMTPS id kj7-20020a17090;',
        '        Thu, 20 Aug 2026 16:35:53 -0700 (PDT)',
        'Received: from sabprogetti.com ([192.210.236.148])',
        '        by smtp-relay.gmail.com with ESMTPS id x9-20020a05;',
        '        Thu, 20 Aug 2026 16:35:51 -0700 (PDT)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@sabeng.it header.s=google header.b=Nx1qKp2L;',
        '       spf=pass (google.com: domain of office@sabeng.it designates 209.85.220.41 as permitted sender) smtp.mailfrom=office@sabeng.it;',
        '       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=sabeng.it',
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sabeng.it; s=google; b=Nx1qKp2L',
        'Message-ID: <3fdbf128-f317-2918-970c-b3015f59f7ea@sabeng.it>',
        'Date: Fri, 21 Aug 2026 01:35:44 +0200',
        'Subject: Document Ready',
        'From: "eDocuSign Signature | (JFKUSES23SPDLT)/EN=RECIPIENTS/LAN=B7A707497B564FD-29431" <office@sabeng.it>',
        'To: recipient@example.com',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><p>A document is waiting for your signature.</p>',
        '<p><a href="https://celiacosaraucania.cl/dc.php?e=recipient@example.com">docusign.com</a></p>',
        '</body></html>',
      ].join('\n'),
    },

    // ========================================================================
    // Fixture #2 — a real legitimate message, kept as the false-positive guard.
    //
    // Received 2026-08-21: a Substack post-reaction notification for the
    // owner's own publication, headers verbatim except truncated tokens and a
    // body reduced to one link. It is the highest-scoring legitimate message
    // seen so far — 30 of the 50 needed — because it is html-only with no
    // X-Mailer, which is exactly how bulk senders build mail.
    //
    // Worth pinning because it stresses three things at once: D3 with the flag
    // ON and an empty allowlist (the earliest hop is Mailgun's HTTP submission,
    // not a provider SMTP relay, so D3 must stay silent); the owner-domain
    // check against a message that genuinely concerns the owner (Sender: and
    // the Return-Path both carry theroadtlv.com, but never the From display
    // name); and the D4 family cap, which keeps html-only + no-mailer below the
    // threshold no matter how ordinary the sender is.
    // ========================================================================
    {
      name: 'Fixture #2: Substack reaction notification — legitimate, must stay clean',
      from: 'Yoel Frischoff from IoT News Digest <reaction@mg1.substack.com>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
      enableReceivedChain: true,
      expectDetectors: ['D4'],
      expectNoDetectors: ['D1', 'D2', 'D3', 'D5', 'owner-impersonation'],
      raw: [
        'Received: by 2002:aa7:dc0b:0:b0:6a2:d1d:9e42 with SMTP id b11csp1278279edu;',
        '        Fri, 21 Aug 2026 08:33:52 -0700 (PDT)',
        'Return-Path: <bounce+61e23f.072c7b-yoel=theroadtlv.com@mg1.substack.com>',
        'Received: from v539.v5375b7fa.use4.send.mailgun.net (v539.v5375b7fa.use4.send.mailgun.net. [159.112.244.39])',
        '        by mx.google.com with UTF8SMTPS id 6a1803df08f44-90c5eeaec8asi66619836d6.102;',
        '        Fri, 21 Aug 2026 08:33:51 -0700 (PDT)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@mg1.substack.com header.s=mailo header.b=SWqEXy85;',
        '       spf=pass (google.com: domain of bounce+61e23f.072c7b-yoel=theroadtlv.com@mg1.substack.com designates 159.112.244.39 as permitted sender) smtp.mailfrom="bounce+61e23f.072c7b-yoel=theroadtlv.com@mg1.substack.com";',
        '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=substack.com',
        'DKIM-Signature: a=rsa-sha256; v=1; c=relaxed/relaxed; d=mg1.substack.com; s=mailo; b=SWqEXy85',
        'Message-Id: <20260817053127.3.43ae793de5251028.6dqp34de@mg1.substack.com>',
        'Date: Fri, 21 Aug 2026 15:33:51 GMT',
        'Subject: Someone liked your post',
        'From: Yoel Frischoff from IoT News Digest <reaction@mg1.substack.com>',
        'To: yoel@theroadtlv.com',
        'Sender: Yoel Frischoff from IoT News Digest <iotdigest@substack.com>',
        'List-Id: <iotdigest.substack.com>',
        'List-Unsubscribe: <https://iotdigest.substack.com/action/disable_email/disable?token=eyJ1c2VyX2lk>',
        'Content-Type: text/html; charset="utf-8"',
        'Content-Transfer-Encoding: quoted-printable',
        'Received: by 67c389bcc96b7429192e9c59b13b09597ea72f7fe254be4accdff052a0ace83f',
        '        with HTTP id 6a886fdf9c7ae96b6f887f7d; Fri, 21 Aug 2026 15:33:51 GMT',
        '',
        '<html><body><a href=3D"https://iotdigest.substack.com/p/iot-news-digest-2633">Re=',
        'ad the post</a></body></html>',
      ].join('\n'),
    },

    // ========================================================================
    // Fixture #5 — a Zoom notification, the "brand mails you about itself" shape.
    //
    // Received 2026-08-25, headers verbatim, body reduced to its links. Scored
    // 60 WATCH on nothing but its footer: the display name "Zoom" resolves to
    // the brand zoom.us, the sender IS zoom.us, and the footer links to
    // zoom.com, linkedin.com, twitter.com, facebook.com, youtube.com and
    // google.com/maps — none of them "the brand", so D5's unrelated-to-brand
    // rule fired on the first one it reached.
    //
    // The rule only means something when the sender is NOT the brand it claims.
    // Adding zoom.com to a brand group would have fixed this one message and
    // left every other brand's social footer still flagged.
    // ========================================================================
    {
      name: 'Fixture #5: Zoom notification with a social footer — legitimate, must stay clean',
      from: 'Zoom <no-reply@zoom.us>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
      enableReceivedChain: true,
      expectDetectors: ['D4'],
      expectNoDetectors: ['D1', 'D2', 'D3', 'D5', 'owner-impersonation'],
      raw: [
        'Delivered-To: yoel@theroadtlv.com',
        'Received: by 2002:aa7:dc0b:0:b0:6a2:d1d:9e42 with SMTP id b11csp5187415edu;',
        '        Tue, 25 Aug 2026 01:44:37 -0700 (PDT)',
        'Return-Path: <bounces+15636778-826c-yoel=theroadtlv.com@bounce-sg.zoom.us>',
        'Received: from o33.sg.zoom.us (o33.sg.zoom.us. [159.183.179.39])',
        '        by mx.google.com with ESMTPS id 41be03b00d2f7-cc199dd3beesi12462846a12.22;',
        '        Tue, 25 Aug 2026 01:44:37 -0700 (PDT)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@zoom.us header.s=sg header.b="CMb3gv7/";',
        '       spf=pass (google.com: domain of bounces+15636778-826c-yoel=theroadtlv.com@bounce-sg.zoom.us designates 159.183.179.39 as permitted sender) smtp.mailfrom="bounces+15636778-826c-yoel=theroadtlv.com@bounce-sg.zoom.us";',
        '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=zoom.us',
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=zoom.us; s=sg; b=CMb3gv7/PCR1',
        'Received: by recvd-d665d4899-stjgp with SMTP id recvd-d665d4899-stjgp-1-6A8D55F3-5D',
        '\t2026-08-25 08:44:35.956472755 +0000 UTC m=+2382678.155411352',
        'Received: from MTU2MzY3Nzg (unknown)',
        '\tby geopod-ismtpd-90 (SG) with HTTP',
        '\tid MEXFlPJEQMyxt95Y9c3o1w',
        '\tTue, 25 Aug 2026 08:44:35.913 +0000 (UTC)',
        'Content-Transfer-Encoding: quoted-printable',
        'Content-Type: text/html; charset=iso-8859-1',
        'Date: Tue, 25 Aug 2026 08:44:35 +0000 (UTC)',
        'From: Zoom <no-reply@zoom.us>',
        'Message-ID: <MEXFlPJEQMyxt95Y9c3o1w@geopod-ismtpd-90>',
        'Subject: Anatoly Zimin has joined your Personal Meeting Room',
        'Feedback-ID: -_pwQUbxR8Koela9eQb97Q:::zoom.us',
        'To: yoel@theroadtlv.com',
        '',
        '<html><body>',
        '<a href=3D"https://zoom.com"><img src=3D"https://file-paa.zoom.us/Iqcx/Zoom_L=',
        'ogo_Bloom_RGB.png" alt=3D"Logo" /></a>',
        '<a href=3D"https://us02web.zoom.us/s/7719754254">Start Meeting</a>',
        '<a href=3D"https://www.linkedin.com/company/zoom/">LinkedIn</a>',
        '<a href=3D"https://twitter.com/zoom">X</a>',
        '<a href=3D"https://www.facebook.com/zoom">Facebook</a>',
        '<a href=3D"https://www.youtube.com/@Zoom">YouTube</a>',
        '<a href=3D"https://blog.zoom.us/">Blog</a>',
        '<a href=3D"https://zoom.com" target=3D"_blank">Zoom.com</a>',
        '<a href=3D"https://www.google.com/maps/place/55+Almaden+Blvd,+San+Jose,+CA+95=',
        '113" target=3D"_blank">55 Almaden Blvd<br/>San Jose, CA 95113</a>',
        '</body></html>',
      ].join('\n'),
    },

    // ========================================================================
    // Fixture #3 — a Google Calendar invitation, the shape v2 kept flagging.
    //
    // Received 2026-08-17, headers sanitized. Every invite trips D5 twice for
    // structural reasons, not adversarial ones: Calendar rewrites description
    // links through google.com/url (so the anchor names the real target and the
    // href names the redirector), and the event link's eid is base64 of
    // "<event id> <invitee address>" (so the recipient is in the URL by design).
    // Score was 65 — above threshold — on a meeting the owner had arranged.
    // ========================================================================
    {
      name: 'Fixture #3: Google Calendar invite with a Zoom link — legitimate, must stay clean',
      from: '"TIMOTHY STATON" <tim@example-consulting.com>',
      expectSpoof: false,
      expectNoDetectors: ['D1', 'D5', 'owner-impersonation'],
      raw: [
        'Delivered-To: recipient@example.com',
        'Return-Path: <tim@example-consulting.com>',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@google.com header.s=20251104;',
        '       spf=none smtp.mailfrom=tim@example-consulting.com;',
        'MIME-Version: 1.0',
        'Sender: Google Calendar <calendar-notification@google.com>',
        'Message-ID: <calendar-7c3801a1-431a-40ee-8e9a-afc199ab1b85@google.com>',
        'Date: Mon, 17 Aug 2026 17:25:18 +0000',
        'Subject: Invitation: Yoel and Tim @ Mon 31 Aug 2026 16:00 - 16:30 (GMT+3)',
        'From: TIMOTHY STATON <tim@example-consulting.com>',
        'To: recipient@example.com',
        'Content-Type: multipart/mixed; boundary="000000000000cal"',
        '',
        '--000000000000cal',
        'Content-Type: text/html; charset="UTF-8"',
        '',
        '<html><body>',
        '<a href="https://www.google.com/url?q=https%3A%2F%2Fus05web.zoom.us%2Fj%2F83174442565&amp;sa=D&amp;source=calendar">https://us05web.zoom.us/j/83174442565</a>',
        // A Zoom URL in the Location field: Calendar wraps it in a Maps search,
        // which unwrapRedirect_ cannot see through — the anchor says zoom.us,
        // the href says google.com. Flagged a real podcast invite on 2026-08-23.
        '<a href="https://www.google.com/maps/search/?api=1&amp;query=https://us05web.zoom.us/j/83174442565">https://us05web.zoom.us/j/83174442565</a>',
        '<a href="https://www.google.com/url?q=https%3A%2F%2Fcalendly.com%2Furl%3Fq%3Dhttps%253A%252F%252Fexample-consulting.com&amp;sa=D&amp;source=calendar">https://example-consulting.com</a>',
        // eid is base64 of "<event id> recipient@example.com" — the invitee is in
        // the URL because that is how Calendar addresses the invitation.
        '<a href="https://calendar.google.com/calendar/event?action=VIEW&amp;eid=MGwyZHUzNWsybDFlMGRxIcmVjaXBpZW50QGV4YW1wbGUuY29t">View all guest info</a>',
        '</body></html>',
        '--000000000000cal',
        'Content-Type: text/calendar; charset="UTF-8"; method=REQUEST',
        '',
        'BEGIN:VCALENDAR',
        'PRODID:-//Google Inc//Google Calendar 70.9054//EN',
        'VERSION:2.0',
        'METHOD:REQUEST',
        'BEGIN:VEVENT',
        'ORGANIZER;CN=TIMOTHY STATON:mailto:tim@example-consulting.com',
        'ATTENDEE;CN=recipient@example.com:mailto:recipient@example.com',
        'END:VEVENT',
        'END:VCALENDAR',
        '--000000000000cal--',
      ].join('\n'),
    },

    // ========================================================================
    // Fixture #4 — a Calendly booking notification, the ESP-bulk shape.
    //
    // Received 2026-08-24, headers verbatim except the recipient address and
    // truncated tokens. A real discovery call the owner had booked scored 70
    // (SPOOF-3-WATCH) on four signals that are all structural properties of
    // transactional mail sent through an ESP: html-only with no X-Mailer (30),
    // a SendGrid Message-ID whose host is the bare internal hostname
    // geopod-ismtpd-115 (10), and the recipient's address in the one-click
    // unsubscribe link that RFC 8058 requires to identify them (30).
    //
    // Fixture #3's invite exemption does not reach this: a booking notification
    // carries no text/calendar part, so the shape had to be fixed at the rule.
    // ========================================================================
    {
      name: 'Fixture #4: Calendly booking notification — legitimate, must stay clean',
      from: 'Kamila Adamatti <notifications@calendly.com>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
      enableReceivedChain: true,
      expectNoDetectors: ['D1', 'D3', 'D5', 'owner-impersonation'],
      raw: [
        'Delivered-To: recipient@example.com',
        'Return-Path: <bounces+13766497-6687-recipient=example.com@em1618.calendly.com>',
        'Received: from o3.sg.calendly.com (o3.sg.calendly.com. [149.72.248.16])',
        '        by mx.google.com with ESMTPS id 6a1803df08f44-90c935c3c90si5936071;',
        '        Mon, 24 Aug 2026 04:30:42 -0700 (PDT)',
        'Received: from MTM3NjY0OTc (unknown) by geopod-ismtpd-115 (SG) with HTTP id',
        '        I7HL0VjBS5OIEGXAWK3D1Q Mon, 24 Aug 2026 11:30:40.670 +0000 (UTC)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@calendly.com header.s=d header.b=cqFH8aph;',
        '       spf=pass (google.com: domain of bounces+13766497-6687-recipient=example.com@em1618.calendly.com designates 149.72.248.16 as permitted sender) smtp.mailfrom="bounces+13766497-6687-recipient=example.com@em1618.calendly.com";',
        '       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=calendly.com',
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=calendly.com; s=d; b=cqFH8aph',
        'Message-ID: <I7HL0VjBS5OIEGXAWK3D1Q@geopod-ismtpd-115>',
        'Date: Mon, 24 Aug 2026 11:30:40 +0000 (UTC)',
        'Subject: Yoel - Discovery Call (30 min) with Kamila Adamatti',
        'From: Kamila Adamatti <notifications@calendly.com>',
        'Reply-To: kamila@toneupbusiness.example',
        'To: Yoel Frischoff <recipient@example.com>',
        'List-Unsubscribe: <https://calendly.com/notification_subscriptions/2bc0447e/opt_out?recipient_email=recipient%40example.com&opt_out_method=1-click>',
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=us-ascii',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        '<html><body>',
        '<p>A new event has been scheduled.</p>',
        '<a href=3D"https://calendly.com/events/23341a35-d67e-4633-9d54-bf70f85a523e">View event</a>',
        '<a href=3D"https://calendly.com/notification_subscriptions/2bc0447e/opt_out?recipient_email=3Drecipient%40example.com">Unsubscribe</a>',
        '</body></html>',
      ].join('\n'),
    },

    // ========================================================================
    // Fixture #6 — a Klaviyo order confirmation, the ecommerce-ESP shape.
    //
    // Received 2026-09-05. Message-ID, Date, Subject and From verbatim; the
    // recipient address is replaced and the Received chain is reduced to the
    // Gmail boundary hop. A real Kideo order confirmation scored exactly 50
    // (SPOOF-3-WATCH) on three signals: the recipient's address in the
    // manage.kmail-lists.com one-click unsubscribe link (30), no X-Mailer or
    // User-Agent (10), and a Message-ID stamped @klaviyomail.com — the
    // generator's own host, which D4 did not know (10).
    //
    // klaviyomail.com is Klaviyo's sending host: every store on Klaviyo
    // stamps its Message-IDs there, so it belongs in
    // D4_KNOWN_MESSAGE_ID_HOSTS beside SendGrid and Mailchimp.
    //
    // The recipient-in-URL hit is the RFC 8058 shape: the real message carries
    // List-Unsubscribe naming manage.kmail-lists.com with the recipient in it,
    // plus List-Unsubscribe-Post: List-Unsubscribe=One-Click. The rule now
    // stands down for hosts the List-Unsubscribe header declares — the
    // sender's own statement of where its list-manage endpoint lives, so no
    // ESP allowlist. This message scores 10 (D4 only) and stays clean.
    // ========================================================================
    {
      name: 'Fixture #6: Klaviyo order confirmation — legitimate, must stay clean',
      from: 'Kideo <contact@kideo.ch>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
      enableReceivedChain: true,
      expectDetectors: ['D4'],
      expectNoDetectors: ['D1', 'D2', 'D3', 'D5', 'owner-impersonation'],
      raw: [
        'Delivered-To: recipient@example.com',
        'List-Unsubscribe:',
        ' <https://manage.kmail-lists.com/subscriptions/unsubscribe?a=V8MCz4&k=8f978ae2c25550db435e7992e00157a7&se=recipient%40example.com>,',
        ' <mailto:unsub1-01M1RGPMA65EBT26PP731G7XJM@shared.klaviyomail.com?subject=request%20unsubscribe>',
        'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
        'Return-Path: <bounces+8012345-67ab-recipient=example.com@klaviyomail.com>',
        'Received: from mail.klaviyomail.com (mail.klaviyomail.com. [205.201.128.0])',
        '        by mx.google.com with ESMTPS id a1b2c3d4e5f6;',
        '        Sat, 5 Sep 2026 03:11:38 -0700 (PDT)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@kideo.ch header.s=kl1;',
        '       spf=pass smtp.mailfrom=bounces+8012345-67ab-recipient=example.com@klaviyomail.com;',
        '       dmarc=pass (p=NONE) header.from=kideo.ch',
        'Message-ID: <01M1RGTQ4S5XBNBE81ZS25WMF4@klaviyomail.com>',
        'Date: Sat, 05 Sep 2026 10:11:38 +0000',
        'Subject: Your order is confirmed',
        'From: Kideo <contact@kideo.ch>',
        'To: recipient@example.com',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="----=_Part_42"',
        '',
        '------=_Part_42',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Your order is confirmed. View your order: https://ctrk.klclick1.com/l/01M1RGTRWRD7BTNH14Z71ADDP7_0',
        '------=_Part_42',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body>',
        '<p>Your order is confirmed.</p>',
        '<a href="https://ctrk.klclick1.com/l/01M1RGTRWRD7BTNH14Z71ADDP7_0">View your order</a>',
        '<a href="https://manage.kmail-lists.com/subscriptions/unsubscribe?a=V8MCz4&k=8f978ae2c25550db435e7992e00157a7&se=recipient%40example.com">Unsubscribe</a>',
        '</body></html>',
        '------=_Part_42--',
      ].join('\n'),
    },

    // --- D3/D4/D5 negatives: real legitimately-relayed mail must stay clean ---
    {
      name: 'D5 negative: genuine DocuSign envelope',
      from: '"DocuSign NA3 System" <dse_na3@docusign.net>',
      expectSpoof: false,
      enableReceivedChain: true,
      raw: [
        'Return-Path: <bounce@docusign.net>',
        'Received: from mail.docusign.net (mail.docusign.net. [64.207.222.10])',
        '        by mx.google.com with ESMTPS id p2-20020a17;',
        '        Wed, 19 Aug 2026 14:02:14 -0700 (PDT)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@docusign.net header.s=dsmail;',
        '       spf=pass smtp.mailfrom=bounce@docusign.net;',
        '       dmarc=pass (p=REJECT) header.from=docusign.net',
        'Message-ID: <7f2c1a90-0000-11f0-9a44-0242ac120002@docusign.net>',
        'Date: Wed, 19 Aug 2026 14:02:11 -0700',
        'Subject: Please DocuSign: Agreement.pdf',
        'From: "DocuSign NA3 System" <dse_na3@docusign.net>',
        'To: recipient@example.com',
        'X-Mailer: DocuSign Notification Service',
        'Content-Type: multipart/alternative; boundary="----=_Part_1"',
        '',
        '------=_Part_1',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><a href="https://na3.docusign.net/Signing/EmailStart.aspx?a=1">Review Document</a></body></html>',
        '------=_Part_1--',
      ].join('\n'),
    },
    {
      name: 'D5 negative: newsletter linking to many unrelated domains',
      from: '"IoT News Digest" <newsletter@substack.com>',
      expectSpoof: false,
      enableReceivedChain: true,
      raw: [
        'Return-Path: <bounce@substack.com>',
        'Received: from mail.substack.com (mail.substack.com. [66.87.11.4])',
        '        by mx.google.com with ESMTPS id b1-20020a05;',
        '        Tue, 18 Aug 2026 06:11:02 -0700 (PDT)',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@substack.com header.s=s1;',
        '       spf=pass smtp.mailfrom=bounce@substack.com;',
        '       dmarc=pass (p=NONE) header.from=substack.com',
        'Message-ID: <20260818131102.abc123@substack.com>',
        'Date: Tue, 18 Aug 2026 09:11:00 -0400',
        'Subject: This week in IoT',
        'From: "IoT News Digest" <newsletter@substack.com>',
        'To: recipient@example.com',
        'Content-Type: multipart/alternative; boundary="----=_Part_9"',
        '',
        '------=_Part_9',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body>',
        '<a href="https://www.theverge.com/2026/08/17/sensors">The Verge on sensors</a>',
        '<a href="https://arstechnica.com/gadgets/2026/08/mesh">Ars on mesh networks</a>',
        '<a href="https://substack.com/unsubscribe?token=xyz">Unsubscribe</a>',
        '</body></html>',
        '------=_Part_9--',
      ].join('\n'),
    },
    {
      name: 'D5 negative: WordPress core file at web root is not a kit path',
      from: '"Site Admin" <admin@somecms.example>',
      expectSpoof: false,
      raw: [
        'Message-ID: <20260818131102.def@somecms.example>',
        'From: "Site Admin" <admin@somecms.example>',
        'To: recipient@example.com',
        'Content-Type: multipart/alternative; boundary="----=_Part_3"',
        'X-Mailer: WordPress',
        '',
        '------=_Part_3',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><a href="https://otherblog.example/wp-login.php?action=rp">Reset your password</a></body></html>',
        '------=_Part_3--',
      ].join('\n'),
    },
    {
      // Counterpart to the fixture below: proves the allowlist is what clears
      // that message, not something incidental about it.
      name: 'D3 positive: same relayed message with an empty allowlist flags',
      from: '"Netlify" <forms@netlify.com>',
      expectSpoof: true,
      enableReceivedChain: true,
      expectDetectors: ['D3'],
      raw: [
        'Received: from mx.google.com by mx.google.com; Tue, 18 Aug 2026 06:11:02 -0700',
        'Received: from sendgrid.net ([167.89.0.1]) by smtp-relay.gmail.com with ESMTPS;',
        '        Tue, 18 Aug 2026 06:11:00 -0700',
        'Authentication-Results: mx.google.com; dkim=pass header.i=@netlify.com; spf=pass; dmarc=pass',
        'Message-ID: <20260818131100.ghi@netlify.com>',
        'Date: Tue, 18 Aug 2026 09:11:00 -0400',
        'From: "Netlify" <forms@netlify.com>',
        'To: recipient@example.com',
        'X-Mailer: Netlify Notifications',
        'Content-Type: multipart/alternative; boundary="----=_Part_4"',
        '',
        '------=_Part_4',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><a href="https://app.netlify.com/sites/example/forms">View submission</a></body></html>',
        '------=_Part_4--',
      ].join('\n'),
    },
    {
      name: 'D3 negative: allowlisted sender/relay pair stays clean',
      from: '"Netlify" <forms@netlify.com>',
      expectSpoof: false,
      enableReceivedChain: true,
      relayAllowlist: ['netlify.com|smtp-relay.gmail.com'],
      raw: [
        'Received: from mx.google.com by mx.google.com; Tue, 18 Aug 2026 06:11:02 -0700',
        'Received: from sendgrid.net ([167.89.0.1]) by smtp-relay.gmail.com with ESMTPS;',
        '        Tue, 18 Aug 2026 06:11:00 -0700',
        'Authentication-Results: mx.google.com; dkim=pass header.i=@netlify.com; spf=pass; dmarc=pass',
        'Message-ID: <20260818131100.ghi@netlify.com>',
        'Date: Tue, 18 Aug 2026 09:11:00 -0400',
        'From: "Netlify" <forms@netlify.com>',
        'To: recipient@example.com',
        'X-Mailer: Netlify Notifications',
        'Content-Type: multipart/alternative; boundary="----=_Part_4"',
        '',
        '------=_Part_4',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><a href="https://app.netlify.com/sites/example/forms">View submission</a></body></html>',
        '------=_Part_4--',
      ].join('\n'),
    },

    {
      // Guards the narrowing above: the recipient-in-URL rule still fires when
      // the address is handed to a host the sender has nothing to do with.
      name: 'D5 positive: recipient address in a link to an unrelated host (scored)',
      from: '"Mail Team" <alerts@ordinary-firm.example>',
      expectSpoof: false,
      expectDetectors: ['D5'],
      raw: [
        'From: "Mail Team" <alerts@ordinary-firm.example>',
        'Delivered-To: recipient@example.com',
        'To: recipient@example.com',
        'Message-ID: <r1@ordinary-firm.example>',
        'Date: Tue, 18 Aug 2026 09:11:00 -0400',
        'X-Mailer: Notifier',
        'Content-Type: multipart/alternative; boundary="b"',
        '',
        '--b',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><a href="https://unrelated-host.example/verify?u=recipient@example.com">Verify</a></body></html>',
        '--b--',
      ].join('\n'),
    },
    {
      name: 'D5 negative: recipient address in a link back to the sender\'s own domain',
      from: '"Mail Team" <alerts@ordinary-firm.example>',
      expectSpoof: false,
      expectNoDetectors: ['D5'],
      raw: [
        'From: "Mail Team" <alerts@ordinary-firm.example>',
        'Delivered-To: recipient@example.com',
        'To: recipient@example.com',
        'Message-ID: <r2@ordinary-firm.example>',
        'Date: Tue, 18 Aug 2026 09:11:00 -0400',
        'X-Mailer: Notifier',
        'Content-Type: multipart/alternative; boundary="b"',
        '',
        '--b',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><a href="https://ordinary-firm.example/opt_out?recipient_email=recipient%40example.com">Unsubscribe</a></body></html>',
        '--b--',
      ].join('\n'),
    },

    {
      name: 'D5 positive: quoted-printable multipart body, bare URL, no anchor tag',
      from: '"Payroll Notice" <hr@ordinary-firm.example>',
      expectSpoof: true,
      expectDetectors: ['D5'],
      raw: [
        'From: "Payroll Notice" <hr@ordinary-firm.example>',
        'To: recipient@example.com',
        'Message-ID: <qp1@ordinary-firm.example>',
        'Content-Type: multipart/alternative; boundary="----=_Part_7"',
        '',
        '------=_Part_7',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        'Review your payslip here: https://someclinic.example/pay=',
        'roll.php?id=3D9921',
        '------=_Part_7--',
      ].join('\n'),
    },

    // --- D2/D4 scored signals: fire, but never flag on their own ---
    {
      name: 'D2 positive: padded directory-style display name (scored, below threshold)',
      from: '"Invoice Service | (QX9912ABCDEF)/EN=RECIPIENTS/LAN=A1B2C3D4E5F60718" <billing@ordinary-supplier.example>',
      expectSpoof: false,
      expectDetectors: ['D2'],
    },
    {
      name: 'D2 negative: ordinary display name produces no signal',
      from: '"Ada Lovelace" <ada@example.org>',
      expectSpoof: false,
      expectNoDetectors: ['D2'],
    },
    {
      name: 'D2 negative: own-domain address in display name is ordinary',
      from: '"billing@acme.example" <no-reply@acme.example>',
      expectSpoof: false,
      expectNoDetectors: ['D2'],
    },
    {
      name: 'D4 positive: html-only, no mailer headers (scored, below threshold)',
      from: '"Weekly Update" <news@plain-sender.example>',
      expectSpoof: false,
      expectDetectors: ['D4'],
      raw: [
        'From: "Weekly Update" <news@plain-sender.example>',
        'To: recipient@example.com',
        'Message-ID: <abc@plain-sender.example>',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body>Hello.</body></html>',
      ].join('\n'),
    },
    {
      name: 'D4 negative: multipart with X-Mailer produces no signal',
      from: '"Weekly Update" <news@plain-sender.example>',
      expectSpoof: false,
      expectNoDetectors: ['D4'],
      raw: [
        'From: "Weekly Update" <news@plain-sender.example>',
        'To: recipient@example.com',
        'Message-ID: <abc@plain-sender.example>',
        'Date: Tue, 18 Aug 2026 09:11:00 -0400',
        'X-Mailer: Apple Mail (2.3731.700.6)',
        'Content-Type: multipart/alternative; boundary="b"',
        '',
        '--b--',
      ].join('\n'),
    },
    {
      name: 'D3 positive: injection into a provider relay from an unrelated host',
      from: '"Accounts Payable" <finance@realcompany.example>',
      expectSpoof: true,
      enableReceivedChain: true,
      expectDetectors: ['D3'],
      raw: [
        'Received: from mx.google.com by mx.google.com; Thu, 20 Aug 2026 16:35:53 -0700',
        'Received: from unrelated-host.xyz ([203.0.113.9]) by smtp-relay.gmail.com with ESMTPS;',
        '        Thu, 20 Aug 2026 16:35:51 -0700',
        'Authentication-Results: mx.google.com; dkim=pass header.i=@realcompany.example; spf=pass; dmarc=pass',
        'Message-ID: <xyz@realcompany.example>',
        'From: "Accounts Payable" <finance@realcompany.example>',
        'To: recipient@example.com',
        'Content-Type: multipart/alternative; boundary="b"',
        '',
        '--b--',
      ].join('\n'),
    },
    {
      name: 'D3 negative: same message with the flag off stays clean',
      from: '"Accounts Payable" <finance@realcompany.example>',
      expectSpoof: false,
      expectNoDetectors: ['D3'],
      raw: [
        'Received: from mx.google.com by mx.google.com; Thu, 20 Aug 2026 16:35:53 -0700',
        'Received: from unrelated-host.xyz ([203.0.113.9]) by smtp-relay.gmail.com with ESMTPS;',
        '        Thu, 20 Aug 2026 16:35:51 -0700',
        'Authentication-Results: mx.google.com; dkim=pass header.i=@realcompany.example; spf=pass; dmarc=pass',
        'Message-ID: <xyz@realcompany.example>',
        'From: "Accounts Payable" <finance@realcompany.example>',
        'To: recipient@example.com',
        'Content-Type: multipart/alternative; boundary="b"',
        '',
        '--b--',
      ].join('\n'),
    },
  ];

  let passed = 0;
  let failed = 0;

  const savedOwnerDomain = _ownerDomainCache;
  const savedReceivedChain = ENABLE_RECEIVED_CHAIN;

  for (const tc of testCases) {
    // Override owner domain for tests that exercise the recipient-domain check
    _ownerDomainCache = Object.prototype.hasOwnProperty.call(tc, 'ownerDomain')
      ? tc.ownerDomain
      : '';
    // D3 ships disabled; fixtures that exercise it turn it on explicitly.
    ENABLE_RECEIVED_CHAIN = tc.enableReceivedChain === true;
    // The shipped allowlist is empty on purpose, so fixtures that exercise it
    // supply their own pairs.
    _relayAllowlistCache = tc.relayAllowlist || null;

    // Build a mock GmailMessage that exercises the real checkForSpoof() code path
    const mockMessage = {
      getFrom: () => tc.from,
      getRawContent: () => tc.raw || tc.rawHeaders || '',
    };
    const result = checkForSpoof(mockMessage);

    const sender = parseSender(tc.from);
    const normalizedName = normalizeToAscii(sender.displayName);
    const fired = result.evidence.map(function (e) { return e.detector; });

    const problems = [];
    if (result.isSpoof !== tc.expectSpoof) {
      problems.push('isSpoof ' + result.isSpoof + ', expected ' + tc.expectSpoof);
    }
    // Detector-level assertions: fixture #1 has to be caught by D1, D3, D4 and
    // D5 independently, so asserting on the verdict alone is not enough — a
    // single load-bearing detector would still pass.
    for (const want of tc.expectDetectors || []) {
      if (fired.indexOf(want) === -1) problems.push(want + ' did not fire');
    }
    for (const unwanted of tc.expectNoDetectors || []) {
      if (fired.indexOf(unwanted) !== -1) problems.push(unwanted + ' fired unexpectedly');
    }

    const status = problems.length === 0 ? 'PASS' : 'FAIL';
    if (status === 'PASS') {
      passed++;
    } else {
      failed++;
    }

    Logger.log(status + ': ' + tc.name);
    Logger.log('  From: ' + tc.from);
    Logger.log('  Normalized name: "' + normalizedName + '"');
    Logger.log('  Score ' + result.score + ' ' + (result.severity || 'clean') +
      ' | detectors: [' + fired.join(', ') + ']');
    if (problems.length) Logger.log('  PROBLEMS: ' + problems.join('; '));
    for (const e of result.evidence) {
      Logger.log('    - ' + e.detector + '(' + e.weight + '): ' + e.note);
    }
    Logger.log('');
  }

  _ownerDomainCache = savedOwnerDomain;
  ENABLE_RECEIVED_CHAIN = savedReceivedChain;
  _relayAllowlistCache = null;

  Logger.log('Results: ' + passed + ' passed, ' + failed + ' failed out of ' + testCases.length + ' tests');
}

/**
 * Diagnostic: find a recent suspicious email and log every step of DKIM detection.
 * Run from the script editor to debug why DKIM checks may be failing.
 */
function debugDkim() {
  const threads = GmailApp.search('in:inbox newer_than:3d', 0, 20);
  const emailLog = []; // Only interesting findings for the email

  let totalMessages = 0;
  let spoofCount = 0;
  let dkimMatchCount = 0;
  let noBoundaryCount = 0;
  let errorCount = 0;

  for (const thread of threads) {
    const messages = thread.getMessages();
    for (const message of messages) {
      totalMessages++;
      const from = message.getFrom();
      const msgLog = []; // Per-message log buffer

      try {
        const raw = message.getRawContent();
        const crlfEnd = raw.indexOf('\r\n\r\n');
        const lfEnd = raw.indexOf('\n\n');
        let headerEnd = crlfEnd;
        if (headerEnd <= 0) headerEnd = lfEnd;

        if (headerEnd <= 0) {
          noBoundaryCount++;
          msgLog.push('  NO HEADER BOUNDARY FOUND (CRLF=' + crlfEnd + ', LF=' + lfEnd + ')');
        } else {
          const headers = raw.substring(0, headerEnd);
          const selectorMatches = headers.match(/\bs=[a-z0-9_-]+/gi);
          const firebaseMatch = /(?:header\.s|\bs)=firebase1\b/.test(headers);
          if (firebaseMatch) {
            dkimMatchCount++;
            msgLog.push('  DKIM selector match! Firebase=' + firebaseMatch);
            msgLog.push('  All s= values: ' + JSON.stringify(selectorMatches));
          }
        }

        const spoofResult = checkForSpoof(message);
        if (spoofResult.isSpoof) {
          spoofCount++;
          msgLog.push('  SPOOF DETECTED [' + spoofResult.severity + ']: ' +
            defangText_(spoofResult.reason));
        }
      } catch (e) {
        errorCount++;
        msgLog.push('  ERROR: ' + e.message);
      }

      // Only include messages with findings
      if (msgLog.length > 0) {
        emailLog.push('--- ' + defangText_(from));
        emailLog.push.apply(emailLog, msgLog);
        emailLog.push('');
      }

      // Always log everything to script editor
      Logger.log('--- ' + defangText_(from) +
        (msgLog.length > 0 ? '\n' + msgLog.join('\n') : ' (clean)'));
    }
  }

  const summary = [
    '=== SUMMARY ===',
    'Messages checked: ' + totalMessages,
    'DKIM selector matches: ' + dkimMatchCount,
    'Spoofs detected: ' + spoofCount,
    'No header boundary: ' + noBoundaryCount,
    'Errors: ' + errorCount,
  ];
  summary.forEach(function(line) { Logger.log(line); });

  // Email only findings + summary
  const recipient = getOwnerEmail_();
  if (recipient) {
    const body = emailLog.length > 0
      ? emailLog.join('\n') + '\n' + summary.join('\n')
      : summary.join('\n') + '\n\nNo issues found in any messages.';
    GmailApp.sendEmail(recipient,
      'Unspoofer debug: ' + spoofCount + ' spoofs, ' + dkimMatchCount + ' DKIM matches, ' + errorCount + ' errors',
      body);
    Logger.log('Debug results emailed to ' + recipient);
  } else {
    Logger.log('Could not determine owner email — check log in script editor');
  }
}

/**
 * Targeted test: find a specific sender and diagnose why detection fails.
 * Run from script editor after changing the search query if needed.
 */
function debugMessage() {
  // Search broadly: anywhere (inbox, spam, trash), multiple terms
  const searches = [
    'from:babyamerica newer_than:7d',
    'from:avacomornami newer_than:7d',
    'from:fsgebaeudeservice newer_than:7d',
    'from:fa-netscher newer_than:7d',
    'in:spam newer_than:7d',
  ];
  var threads = [];
  for (var i = 0; i < searches.length; i++) {
    threads = GmailApp.search(searches[i], 0, 5);
    if (threads.length > 0) {
      Logger.log('Found with query: ' + searches[i]);
      break;
    }
  }
  if (threads.length === 0) {
    var recipient = getOwnerEmail_();
    if (recipient) {
      GmailApp.sendEmail(recipient, 'debugMessage: nothing found',
        'Tried these searches:\n' + searches.join('\n') + '\n\nNo messages matched.');
    }
    Logger.log('No messages found with any search');
    return;
  }
  const message = threads[0].getMessages()[0];
  const from = message.getFrom();
  const lines = ['From: ' + from, ''];

  try {
    const raw = message.getRawContent();
    lines.push('Raw content length: ' + raw.length);
    lines.push('First 500 chars:');
    lines.push(defangText_(raw.substring(0, 500)));
    lines.push('');

    const crlfEnd = raw.indexOf('\r\n\r\n');
    const lfEnd = raw.indexOf('\n\n');
    lines.push('CRLF boundary at: ' + crlfEnd);
    lines.push('LF boundary at: ' + lfEnd);

    let headerEnd = crlfEnd;
    if (headerEnd <= 0) headerEnd = lfEnd;

    if (headerEnd > 0) {
      const headers = raw.substring(0, headerEnd);
      lines.push('Header length: ' + headers.length);
      const selectors = headers.match(/\bs=[a-z0-9_-]+/gi);
      lines.push('All s= values: ' + JSON.stringify(selectors));

      const fb = /(?:header\.s|\bs)=firebase1\b/.test(headers);
      lines.push('Firebase match: ' + fb);
    } else {
      lines.push('NO HEADER BOUNDARY FOUND');
    }

    lines.push('');
    const result = checkForSpoof(message);
    lines.push('checkForSpoof: isSpoof=' + result.isSpoof +
      ' score=' + result.score + ' severity=' + (result.severity || 'clean'));
    lines.push('reason: ' + defangText_(result.reason));
    lines.push('details: ' + defangText_(result.details));
  } catch (e) {
    lines.push('ERROR: ' + e.message);
    lines.push('Stack: ' + e.stack);
  }

  const body = lines.join('\n');
  Logger.log(body);

  recipient = getOwnerEmail_();
  if (recipient) {
    GmailApp.sendEmail(recipient, 'Unspoofer debugMessage: ' + from, body);
    Logger.log('Emailed to ' + recipient);
  }
}

/**
 * Clears the processed message cache and immediately re-scans.
 * Use after deploying detection changes to re-check previously missed messages.
 */
function rescanInbox() {
  Logger.log('Clearing processed message cache...');
  clearProcessedCache();
  Logger.log('Cache cleared. Starting fresh scan...');
  scanInbox();

  // Also email a full report of what was scanned
  const threads = GmailApp.search(SCAN_QUERY, 0, 100);
  const lines = ['rescanInbox report — query: ' + SCAN_QUERY, ''];
  let count = 0;
  for (const thread of threads) {
    const messages = thread.getMessages();
    for (const message of messages) {
      count++;
      const from = message.getFrom();
      const subject = message.getSubject();
      const result = checkForSpoof(message);
      lines.push(count + '. ' +
        (result.isSpoof ? result.severity + ' (' + result.score + ')' : 'clean') +
        ' | ' + defangText_(from) + ' | ' + defangText_(subject) +
        (result.isSpoof ? ' | ' + defangText_(result.reason) : ''));
    }
  }
  lines.push('');
  lines.push('Total: ' + count + ' messages');

  const recipient = getOwnerEmail_();
  if (recipient) {
    GmailApp.sendEmail(recipient, 'Unspoofer rescan report: ' + count + ' messages', lines.join('\n'));
  }
}
