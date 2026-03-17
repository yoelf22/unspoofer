/**
 * Unspoofer — Gmail display-name spoof detector.
 * Entry points: setup(), scanInbox(), uninstall(), testDetection()
 */

const LABEL_NAME = 'SPOOF-ALERT';
const SCAN_QUERY = 'in:inbox newer_than:1d';
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

  // Create a new 15-minute trigger
  ScriptApp.newTrigger('scanInbox')
    .timeBased()
    .everyMinutes(15)
    .create();
  Logger.log('Created 15-minute trigger for scanInbox');

  Logger.log('Setup complete. Unspoofer is active.');
}

/**
 * Main scan function — called by trigger every 15 minutes.
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

  Logger.log('Scan complete. Scanned: ' + scannedCount +
    ', Skipped (cached): ' + skippedCount +
    ', Spoofs found: ' + spoofCount);
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
  ];

  let passed = 0;
  let failed = 0;

  for (const tc of testCases) {
    const sender = parseSender(tc.from);
    const normalizedName = normalizeToAscii(sender.displayName);
    const brandMatch = findSpoofedBrand(normalizedName);

    let isSpoof = false;
    if (sender.email) {
      const emailDomain = sender.email.split('@')[1];
      // Check suspicious platforms first
      if (isSuspiciousPlatform(emailDomain)) {
        isSpoof = true;
      } else if (brandMatch) {
        const actualRoot = extractRootDomain(emailDomain);
        const brandRoot = extractRootDomain(brandMatch.domain);
        isSpoof = actualRoot !== brandRoot && !isRelatedBrandDomain(brandRoot, actualRoot);
      }
    }

    const status = isSpoof === tc.expectSpoof ? 'PASS' : 'FAIL';
    if (status === 'PASS') {
      passed++;
    } else {
      failed++;
    }

    Logger.log(status + ': ' + tc.name);
    Logger.log('  From: ' + tc.from);
    Logger.log('  Normalized name: "' + normalizedName + '"');
    Logger.log('  Brand match: ' + (brandMatch ? brandMatch.domain : 'none'));
    Logger.log('  Detected as spoof: ' + isSpoof + ' (expected: ' + tc.expectSpoof + ')');
    Logger.log('');
  }

  Logger.log('Results: ' + passed + ' passed, ' + failed + ' failed out of ' + testCases.length + ' tests');
}
