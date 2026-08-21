/**
 * Local runner for testDetection() — no Apps Script editor needed.
 *
 *   node test-local.js
 *
 * The .gs files are plain JS. They are concatenated into ONE vm script (one
 * script, so top-level const/let/function share a scope — testDetection()
 * reassigns module-level `let`s like _ownerDomainCache) with the Apps Script
 * globals stubbed. Exits non-zero if any case fails.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// Load order matters: consts are in TDZ until their line executes.
const FILES = ['Homoglyphs.gs', 'Headers.gs', 'Brands.gs', 'DisplayName.gs', 'Fingerprint.gs', 'Links.gs', 'Provenance.gs', 'SpoofDetector.gs', 'Code.gs'];

const source = FILES
  .filter((f) => fs.existsSync(path.join(__dirname, f)))
  .map((f) => '// ===== ' + f + ' =====\n' + fs.readFileSync(path.join(__dirname, f), 'utf8'))
  .join('\n') + '\ntestDetection();\n';

const out = [];
const props = {};
const sandbox = {
  Logger: { log: (m) => out.push(String(m)) },
  PropertiesService: {
    getScriptProperties: () => ({
      getProperty: (k) => (k in props ? props[k] : null),
      setProperty: (k, v) => { props[k] = v; },
      deleteProperty: (k) => { delete props[k]; },
    }),
  },
  Session: {
    getEffectiveUser: () => ({ getEmail: () => '' }),
    getActiveUser: () => ({ getEmail: () => '' }),
  },
  GmailApp: {
    getUserLabelByName: () => null,
    createLabel: (n) => ({ getName: () => n }),
    search: () => [],
    sendEmail: () => {},
  },
  ScriptApp: { getProjectTriggers: () => [] },
  Utilities: {
    DigestAlgorithm: { MD5: 'MD5' },
    base64Encode: (str) => Buffer.from(str, 'utf8').toString('base64'),
    base64Decode: (str) => Array.from(Buffer.from(str, 'base64')),
    newBlob: (bytes) => ({ getDataAsString: () => Buffer.from(bytes).toString('utf8') }),
    computeDigest: (_alg, str) =>
      Array.from(require('crypto').createHash('md5').update(str).digest())
        .map((b) => (b > 127 ? b - 256 : b)),
  },
  console,
};

try {
  vm.runInNewContext(source, sandbox, { filename: 'unspoofer.gs' });
} catch (e) {
  console.error('LOAD/RUN ERROR: ' + e.message + '\n' + e.stack);
  process.exit(2);
}

// D5's standing rule: this file must never make a network request.
const links = path.join(__dirname, 'Links.gs');
const linksCode = fs.existsSync(links)
  ? fs.readFileSync(links, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '')
  : '';
if (/UrlFetchApp/.test(linksCode)) {
  console.error('FAIL: Links.gs references UrlFetchApp. D5 is parse-only — see the header comment.');
  process.exit(1);
}

const log = out.join('\n');
const summary = log.match(/^Results: (\d+) passed, (\d+) failed/m);
if (!summary) {
  console.error(log);
  console.error('\nNo "Results:" line found.');
  process.exit(2);
}

// Only echo failures unless -v.
if (process.argv.includes('-v')) {
  console.log(log);
} else {
  log.split('\n\n').filter((b) => b.startsWith('FAIL:')).forEach((b) => console.log(b + '\n'));
}
console.log(summary[0]);
process.exit(Number(summary[2]) > 0 ? 1 : 0);
