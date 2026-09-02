# Changelog

## 2026-09-02 — D5 anchor-mismatch false positive on calendar invites

A Google Calendar invitation for a podcast recording scored 65
(SPOOF-3-WATCH). The organizer had typed the Zoom URL into the event's
Location field. Calendar renders a location as a Maps search link, so the
anchor text said `zoom.us` and the href said `google.com/maps/search/?query=…`
— exactly the shape the anchor-mismatch rule looks for, on a meeting the owner
had arranged himself. (The recipient-in-URL half of that score was already
fixed on 2026-08-23.)

**D5's anchor-mismatch rule now stands down on calendar invites**, the same
`isCalendarInvite_` gate the recipient-in-URL rule already uses. Calendar
rewrites every anchor it renders — description links through `google.com/url`,
locations through `google.com/maps/search` — so on an invite the text names
the real target and the href names Google, always. Fixture #3 gains the
Location-field shape and fails on the old code.

"Zoom" is what people call a video call, and a meeting link in the Location
field is how most of them send it. The rule is untouched outside invites.

## 2026-08-25 — D5 false positive on a brand's own transactional mail

A Zoom "someone joined your meeting room" notification scored 60
(SPOOF-3-WATCH) on nothing but its footer. Display name "Zoom" resolves to the
brand `zoom.us`, the sender **is** `zoom.us`, and the footer links to
`zoom.com`, `linkedin.com`, `twitter.com`, `facebook.com`, `youtube.com` and
`google.com/maps` — none of which is "the brand", so the unrelated-to-brand
rule fired on the first one it reached.

**D5's unrelated-to-brand rule now stands down when the sender is the brand.**
"Claims X but links elsewhere" only carries signal when the sender is *not* X.
When it is, the rule degenerates into "a brand may only ever link to itself",
which is false for every brand footer in existence. The sender-relative rules
(root script, recipient-in-URL, anchor mismatch) are untouched and still cover
this message; Fixture #1, where the sender is `sabeng.it` and the claimed brand
is DocuSign, still fires the rule.

Adding `zoom.com` to a brand group would have cleared this one message and left
every other brand's social footer flagged — and `linkedin.com` would simply have
fired next. Fixed at the rule.

D4's html-only + no-mailer 30 remains and is correct. Fixture #5 pins the case.
65/65 pass.

## 2026-08-24 — D5 + D4 false positive on ESP transactional mail

A Calendly booking notification for a call the owner had booked scored 70
(SPOOF-3-WATCH). All four signals are structural properties of transactional
mail sent through an ESP, not evidence:

- **The recipient-in-URL rule now requires a host unrelated to the sender.**
  Your address in a link back to the domain that signed the message is that
  sender addressing you — every bulk mailer puts it in the unsubscribe link, and
  RFC 8058 one-click *requires* the link to identify the recipient. The signal
  the rule exists for is a kit on somebody else's host pre-filling your address
  on a login page, which is unchanged. Fixture #1 still fires it.
- **A Message-ID host with no dot is no longer a signal.** SendGrid stamps
  `<...@geopod-ismtpd-115>` — the generator's internal hostname, not a domain.
  It can agree with nothing, so it says nothing. `sendgrid.net` was already on
  the known-generator list and never matched, because SendGrid does not use it
  here.

D4's html-only + no-mailer 30 still fires and is correct: this really is
script-assembled mail. It stays below the 50 threshold on its own, which is the
behaviour Fixture #2 was pinned to guard.

Fixture #3's invite exemption could not reach this — a booking notification
carries no `text/calendar` part — so both fixes are at the rule, not the shape.
Fixture #4 pins the case: without them it reproduces the exact 70 and all four
evidence lines. Two smaller cases guard the narrowing in both directions.
64/64 pass.

## 2026-08-23 — D5 false positive on calendar invitations

A Google Calendar invitation for a podcast the owner had arranged scored 65
(SPOOF-3-WATCH). Both D5 hits were structural properties of every invite, not
signals:

- **Redirect wrappers are now unwrapped before a link is judged.** Calendar
  rewrites description links through `google.com/url?q=`, and Calendly wraps
  user-supplied links through `calendly.com/url?q=` — so the anchor text named
  the real target and the href named the redirector, which the anchor-mismatch
  rule read as a lie. Unwrapping (up to 3 nested hops, only for
  `D5_REDIRECT_ROOTS`) also strengthens the other rules: an open-redirect lure
  is now judged on where it actually lands. Only known redirectors are
  unwrapped — otherwise any phishing host could claim a brand by naming it in
  its own `?url=` parameter.
- **The recipient-in-URL rule is skipped for real invitations** (a
  `text/calendar` part plus an ICS `METHOD:REQUEST|CANCEL|REPLY`). Calendar's
  `eid` is base64 of "&lt;event id&gt; &lt;invitee address&gt;" — the invitee is
  in the URL because that is how the invitation is addressed.

Fixture #3 pins the case: without the fix it reproduces the exact 65 and both
evidence lines. D4's no-mailer 10 still fires on invites, which is correct and
harmless on its own.

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
  provider SMTP relay from a host unrelated to the sending domain. Its relay
  allowlist ships **empty** — a guessed entry permanently exempts a domain +
  relay pair an attacker could then use, which is worse than no entry.
  `reportRelayPairs()` prints the pairs actually present in your mail and
  `addRelayPair()` records the ones you recognize, in Script Properties.

  D3 was written to ship disabled, and was **enabled the same day on
  measurement**: `reportRelayPairs()` over 97 messages of real inbox+spam found
  exactly one provider-relay submission, and it was the sabeng.it attack. An
  independent 25-message Gmail API sample over 7 days found none. The five
  allowlist entries originally drafted from assumption (Substack, KDP,
  IngramSpark, Netlify, Amazon) would all have been noise — none of those
  senders relays through a provider SMTP relay in this mailbox.

  Known gap: `PROVIDER_RELAYS` covers Google's submission hosts well and
  Microsoft's thinly. Exchange Online internal routing (`*.prod.outlook.com`)
  is correctly not matched, but M365 submission paths have more host shapes than
  Google's, so D3's coverage of Office 365 senders is weaker. That is a
  false-negative gap, not a false-positive one.

- `reportRelayPairs()` deliberately does not print a ready-to-paste
  `addRelayPair()` call next to a flagged pair. The first real run flagged
  exactly one pair and it was the phish; a copyable command to allowlist it
  would have been a copyable command to disarm the detector.
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
- Fixture #2: a real Substack post-reaction notification of 2026-08-21, kept as
  the false-positive guard. It scores 30 of the 50 needed — html-only with no
  `X-Mailer`, which is simply how bulk senders build mail — and is the
  highest-scoring legitimate message seen so far. It pins three things at once:
  D3 stays silent with the flag ON and the allowlist empty (Mailgun submits over
  HTTP, so no provider SMTP relay is ever entered), the owner-domain check does
  not fire on a message that genuinely concerns the owner (`theroadtlv.com` is
  in the Return-Path but never in the From display name), and the D4 family cap
  keeps html-only plus no-mailer below the threshold.

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
