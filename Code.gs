/**
 * Unspoofer — Gmail display-name spoof detector.
 * Entry points: setup(), scanInbox(), uninstall(), testDetection()
 */

const LABEL_NAME = 'SPOOF-ALERT';
const SCAN_QUERY = '{in:inbox in:spam} newer_than:3d';
const EXECUTION_TIME_LIMIT_MS = 5 * 60 * 1000; // 5 minutes (safety margin under 6-min limit)

/**
 * Creates the SPOOF-ALERT label (idempotent) and sets up a 15-minute trigger.
 */
function setup() {
  // Create label if it doesn't exist
  let label = GmailApp.getUserLabelByName(LABEL_NAME);
  if (!label) {
    label = GmailApp.createLabel(LABEL_NAME);
    Logger.log('Created label: ' + LABEL_NAME);
  } else {
    Logger.log('Label already exists: ' + LABEL_NAME);
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
  const label = GmailApp.getUserLabelByName(LABEL_NAME);
  if (!label) {
    Logger.log('SPOOF-ALERT label not found. Run setup() first.');
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
        const msgId = message.getId();

        // Skip already-processed messages
        if (isProcessed(msgId)) {
          skippedCount++;
          continue;
        }

        scannedCount++;
        const result = checkForSpoof(message);

        if (result.isSpoof) {
          // Apply label to the thread
          thread.addLabel(label);
          // Star the specific message
          message.star();

          const sender = parseSender(message.getFrom());
          spoofDetails.push({
            subject: message.getSubject(),
            email: sender.email,
            displayName: sender.displayName,
            reason: result.reason,
          });

          spoofCount++;
          Logger.log('SPOOF DETECTED: ' + result.reason);
          Logger.log('  Details: ' + result.details);
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
 * Sends an email alert with an HTML table summarizing detected spoofs.
 * @param {Array<{subject: string, email: string, displayName: string, reason: string}>} spoofs
 */
function sendSpoofAlert_(spoofs) {
  const recipient = getOwnerEmail_();
  if (!recipient) {
    Logger.log('Could not determine owner email — skipping alert');
    return;
  }

  const rows = spoofs.map(function(s) {
    const esc = function(str) { return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); };
    return '<tr>' +
      '<td style="padding:8px;border:1px solid #ddd">' + esc(s.subject) + '</td>' +
      '<td style="padding:8px;border:1px solid #ddd">' + esc(s.email) + '</td>' +
      '<td style="padding:8px;border:1px solid #ddd">' + esc(s.displayName) + '</td>' +
      '<td style="padding:8px;border:1px solid #ddd">' + esc(s.reason) + '</td>' +
      '</tr>';
  }).join('');

  const html = '<h2>Spoof Alert: ' + spoofs.length + ' suspicious message' +
    (spoofs.length > 1 ? 's' : '') + ' detected</h2>' +
    '<table style="border-collapse:collapse;width:100%;font-family:sans-serif;font-size:14px">' +
    '<tr style="background:#f44336;color:white">' +
    '<th style="padding:8px;border:1px solid #ddd;text-align:left">Subject</th>' +
    '<th style="padding:8px;border:1px solid #ddd;text-align:left">Sender Email</th>' +
    '<th style="padding:8px;border:1px solid #ddd;text-align:left">Display Name</th>' +
    '<th style="padding:8px;border:1px solid #ddd;text-align:left">Reason</th>' +
    '</tr>' + rows + '</table>' +
    '<p style="color:#666;font-size:12px">Sent by Unspoofer. These messages have been labeled SPOOF-ALERT and starred in your inbox.</p>';

  GmailApp.sendEmail(recipient,
    'Spoof Alert: ' + spoofs.length + ' suspicious message' + (spoofs.length > 1 ? 's' : '') + ' found',
    '', { htmlBody: html });
  Logger.log('Alert email sent to ' + recipient);
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

  Logger.log('Uninstall complete. The SPOOF-ALERT label is preserved for review.');
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
      expectSpoof: false, // "netflio" doesn't match "netflix"
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
  ];

  let passed = 0;
  let failed = 0;

  const savedOwnerDomain = _ownerDomainCache;

  for (const tc of testCases) {
    // Override owner domain for tests that exercise the recipient-domain check
    _ownerDomainCache = Object.prototype.hasOwnProperty.call(tc, 'ownerDomain')
      ? tc.ownerDomain
      : '';
    // Build a mock GmailMessage that exercises the real checkForSpoof() code path
    const mockMessage = {
      getFrom: () => tc.from,
      getRawContent: () => tc.rawHeaders || '',
    };
    const result = checkForSpoof(mockMessage);

    const sender = parseSender(tc.from);
    const normalizedName = normalizeToAscii(sender.displayName);

    const status = result.isSpoof === tc.expectSpoof ? 'PASS' : 'FAIL';
    if (status === 'PASS') {
      passed++;
    } else {
      failed++;
    }

    Logger.log(status + ': ' + tc.name);
    Logger.log('  From: ' + tc.from);
    Logger.log('  Normalized name: "' + normalizedName + '"');
    Logger.log('  Detected as spoof: ' + result.isSpoof + ' (expected: ' + tc.expectSpoof + ')');
    if (result.isSpoof) Logger.log('  Reason: ' + result.reason);
    Logger.log('');
  }

  _ownerDomainCache = savedOwnerDomain;

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
          msgLog.push('  SPOOF DETECTED: ' + spoofResult.reason);
        }
      } catch (e) {
        errorCount++;
        msgLog.push('  ERROR: ' + e.message);
      }

      // Only include messages with findings
      if (msgLog.length > 0) {
        emailLog.push('--- ' + from);
        emailLog.push.apply(emailLog, msgLog);
        emailLog.push('');
      }

      // Always log everything to script editor
      Logger.log('--- ' + from + (msgLog.length > 0 ? '\n' + msgLog.join('\n') : ' (clean)'));
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
    lines.push(raw.substring(0, 500));
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
    lines.push('checkForSpoof: isSpoof=' + result.isSpoof);
    lines.push('reason: ' + result.reason);
    lines.push('details: ' + result.details);
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
      lines.push(count + '. ' + (result.isSpoof ? 'SPOOF' : 'clean') +
        ' | ' + from + ' | ' + subject +
        (result.isSpoof ? ' | ' + result.reason : ''));
    }
  }
  lines.push('');
  lines.push('Total: ' + count + ' messages');

  const recipient = getOwnerEmail_();
  if (recipient) {
    GmailApp.sendEmail(recipient, 'Unspoofer rescan report: ' + count + ' messages', lines.join('\n'));
  }
}
