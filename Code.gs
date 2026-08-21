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
