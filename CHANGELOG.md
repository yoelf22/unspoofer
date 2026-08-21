# Changelog

## 2026-08-21 — v2: provenance and internal consistency

**The v2 thesis.** v1 assumed spoofing shows up in the From header: a display
name that lies, a homoglyph that hides, a brand domain that doesn't match the
sender. That assumption holds only for attackers who cannot authenticate. A
sufficiently well-resourced attacker passes every check — a message relayed
through a compromised organization's own authorized Google Workspace SMTP relay
gets a clean SPF pass, a valid DKIM signature from the real domain, and a DMARC
alignment that is genuinely correct, because the relay really is authorized to
send for that domain. The From header is not lying; the composer is. That
message reaches the inbox rather than spam *because* it authenticates. So v2
treats authentication result and provenance as independent signals and scores
them separately, and moves detection from "is the From header lying" to "is this
message internally consistent, and did it enter the mail system where it should
have". Authenticated **and** anomalous is now its own highest-priority verdict.

### Added
- **D1 — brand near-miss matching.** Brand tokens with glued prefixes
  (`edocusign`), numeric suffixes (`docusign24`), separator splits
  (`docu-sign`), and typos within edit distance 2. Compares an identified
  brand's domain against both the From domain and the DKIM `d=` domain.
  Length-gated: affix matching needs a 6-character brand, edit distance needs 8,
  or "groups" matches `ups` and "notice" matches `notion`. Deliberately
  asymmetric about affixes: characters before a brand always count, characters
  after it only count when they contain a digit. A symmetric rule matched 23 of
  55 ordinary display names in a sweep (Squares Bakery, Amazonia Travel,
  Cloudflared Tunnel) — an alphabetic tail is English, not a typo-squat.
  DocuSign and Adobe added to the brand list — DocuSign was previously trusted
  as an on-behalf-of service while being undetectable as an impersonated brand.
- **D2 — display-name obfuscation** (`DisplayName.gs`). Scored, never a hard
  fail: over-length names, pseudo-directory syntax, embedded off-domain
  addresses, opaque identifier runs.
- **D3 — Received-chain injection point** (`Provenance.gs`). Submission into a
  provider SMTP relay from a host unrelated to the sending domain. Ships
  **disabled** behind `ENABLE_RECEIVED_CHAIN`, and its relay allowlist ships
  **empty** — a guessed entry permanently exempts a domain + relay pair an
  attacker could then use, which is worse than no entry. `reportRelayPairs()`
  prints the pairs actually present in your mail and `addRelayPair()` records
  the ones you recognize, in Script Properties.
- **D4 — MUA fingerprint consistency** (`Fingerprint.gs`). Scored: html-only
  bodies, absent mailer headers, unrecognized Message-ID hosts, small-hours
  composition in the sender's own stated timezone.
- **D5 — link analysis** (`Links.gs`), parse only. Bare scripts at the web root
  of unrelated hosts, links unrelated to both brand and sender, the recipient's
  address encoded into a URL, anchor text disagreeing with its href. The test
  suite fails if `UrlFetchApp` appears anywhere in the file.
- **Composite scoring with an evidence list.** Every verdict carries the
  detectors that fired, their weights and their notes, into the log and the
  alert email. Hard detectors weigh 100 and flag alone (v1 behaviour, kept);
  scored detectors are capped at 45 each, below the threshold of 50.
- **Severity labels**: `SPOOF-1-CRITICAL`, `SPOOF-2-HIGH`, `SPOOF-3-WATCH`.
  Severity is carried by the number and the word — no label colours are set at
  all, because a tier distinguished by hue is unreadable to a red/green
  colourblind maintainer.
- **URL defanging on every output path** — alert email, execution log, and both
  debug reports — including URLs inside subjects and display names.
- `Headers.gs`: raw content is fetched and parsed once per message and shared by
  every detector, instead of each one calling `getRawContent()` again.
- `test-local.js`: runs `testDetection()` under Node with the Apps Script globals
  stubbed. No editor, no Google account, non-zero exit on failure.
- Fixture #1: the sabeng.it message of 2026-08-20, with sanitized headers,
  asserted to be caught by D1, D3, D4 and D5 independently. Negative fixtures
  from real legitimate mail: a genuine DocuSign envelope, a Substack send, a
  WordPress password reset, a Netlify form notification.

### Changed
- `checkForSpoof()` returns `{isSpoof, score, severity, reason, brand, details,
  evidence}`. `isSpoof` is derived from the score and kept, so existing call
  sites are unaffected.
- `checkSuspiciousDkimSelector()` takes a parsed context instead of a message.
- The alert email shows severity, score and the full evidence list per message,
  and no longer uses a red header.

### Not implemented, deliberately
- **D6 — first-contact correlation** against Sent. Costs a Gmail search per
  message and is the weakest signal on its own.
- **ASN/geo enrichment of the submission IP.** Referencing `UrlFetchApp`
  anywhere makes Apps Script demand the `script.external_request` scope from
  every installer, including everyone who leaves the flag off. `ENABLE_IP_ENRICHMENT`
  and instructions are in place; the call is not. See README.

### Fixed
- The 2026-03-18 entry below claims Alibaba Cloud DirectMail detection was
  added. It was not: `SUSPICIOUS_DKIM_SELECTORS` has only ever contained the
  Firebase selector, and a test fixture asserts that an `aliyun-*` selector stays
  clean. The entry was wrong when written.
- README said the trigger runs every 15 minutes. It has been 10 since
  2026-03-27.

## 2026-07-18

### Added
- Detect owner-domain (self) impersonation: flag external senders that put your
  own organization's name/domain in the From display name, e.g.
  "Docs@theroadtlv" <documents@asecureltd.com>. Includes an allowlist of
  recognized on-behalf-of services so legitimate form/e-sign mail still passes.

## 2026-04-29

### Fixed
- Form-service notifications no longer flagged as spoofs. Generic domain-in-display-name check now skips when the implied domain matches the inbox owner's own domain — catches Netlify Forms, Formspree, and similar services that put the customer's domain in the display name (e.g., `"theroadtlv.com" <formresponses@netlify.com>`).

## 2026-03-30

### Added
- Generic domain-in-display-name mismatch detection: if a display name contains a domain (e.g., "Support - coolstartup.com") that doesn't match the sender's actual domain, the email is flagged without needing a brand list entry.
- OpenAI (`openai.com`) and ChatGPT (`chatgpt.com`) brand coverage.

## 2026-03-27

### Changed
- Increased scan interval from 1 minute to 10 minutes to avoid Gmail API quota exhaustion.

## 2026-03-24

### Changed
- Reduced scan interval from 15 minutes to 1 minute to close the window where spoofed emails reach Apple Mail before detection.

## 2026-03-23

### Added
- MIT license.
- Examples with spoof detection screenshots.

## 2026-03-22

### Added
- Email alert with HTML table when spoofs are detected, showing subject, sender, display name, and detection reason.
- Brand name detection in email local parts (e.g., `domains.notifications.wix.renew@investireinlettonia.it`).
- DKIM debug logging to diagnose detection failures on real messages.
- `debugDkim()` summary output with totals for messages checked, matches, spoofs, and errors.
- `debugMessage()` function to diagnose a specific sender with raw header diagnostics.
- Email delivery for `debugDkim()` and `debugMessage()` results instead of console-only logging.
- Email report to `rescanInbox()` showing all scanned messages with spoof results.
- Spam folder scanning — phishing emails in spam still sync to mail clients like Apple Mail.

### Changed
- Lowered short brand threshold from 4 to 2 characters, enabling detection of 3-letter brands (wix, ups, dhl).
- Widened scan window from 1 day to 3 days to prevent missing emails between deployments.
- Broadened `debugMessage()` search across spam and multiple sender domains.

### Fixed
- Email sending: switched to `GmailApp.sendEmail` and `Session.getEffectiveUser()` for Workspace account compatibility.
- `var`/`const` conflict in `debugMessage()`.
- Only include positive findings in `debugDkim()` email output.

### Removed
- Debug logging from `checkSuspiciousDkimSelector` — detection confirmed working in production.

## 2026-03-20

### Added
- `debugDkim()` function to log every step of DKIM detection on real inbox messages.
- `rescanInbox()` function to clear processed cache and re-scan for missed messages.

## 2026-03-19

### Fixed
- Handle both `\r\n` and `\n` line endings in raw message headers. Gmail's `getRawContent()` may normalize line endings, which broke DKIM selector detection.

## 2026-03-18

### Added
- Alibaba Cloud DirectMail detection via DKIM selector prefix matching (e.g., `aliyun-ap-southeast-1`).

### Changed
- Pre-compile DKIM selector regex patterns at module load for performance.
- Cache whitelist in memory per execution.
- Refactored `testDetection()` to call `checkForSpoof()` with mocks instead of reimplementing the detection pipeline.

### Fixed
- Platform checks now run before requiring a display name. Emails without a display name were skipping all detection.
- Return `null` immediately for malformed messages without header boundary.

## 2026-03-17

### Added
- Suspicious platform detection for abused sending domains (firebaseapp.com, appspot.com).
- Firebase phishing detection via DKIM selector — attackers register custom domains in Firebase but the `firebase1` DKIM selector remains in headers.

## 2026-03-16

### Added
- Initial release: Gmail display-name spoof detector.
- Unicode homoglyph normalization (Cyrillic, Greek, fullwidth characters).
- 50+ brand domain matching.
- Automatic scanning every 15 minutes with SPOOF-ALERT labeling.
- Brand groups for multi-domain companies (Google/YouTube, Microsoft/Outlook) to reduce false positives.
- Sender whitelist stored in Script Properties.
