# Changelog

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
