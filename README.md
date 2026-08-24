# Unspoofer — Gmail phishing detector

<img src="images/mascot.png" align="right" width="200" alt="Unspoofer mascot — a detective fox examining an envelope with a magnifying glass">

If you run Google Workspace as your email server, this is for you.

A Google Apps Script that flags phishing that reaches the inbox. It started as a
display-name spoof detector — sender shows "Wіх.соm" in Cyrillic, mail actually
comes from `info@bistro-pub.de`. v2 goes after the harder case: mail that passes
every authentication check and is still not what it claims to be.

## The v2 thesis

**Authentication result and provenance are independent signals, and Unspoofer
scores them separately.**

SPF, DKIM and DMARC passing proves a message traversed infrastructure authorized
to send for that domain. It says nothing about who composed it. When an attacker
gets into a legitimate organization's Workspace tenant, every check aligns
perfectly — because the relay really is authorized. That message lands in the
inbox, not spam, precisely because it authenticates.

So v2 stops treating a clean auth result as background and starts treating
**authenticated *and* anomalous** as the thing worth looking at. Detection moved
from "is the From header lying" to "is this message internally consistent, and
did it enter the mail system where it should have".

## How it works

1. Runs every 10 minutes via a time-driven trigger
2. Scans inbox **and spam** from the last 3 days (spam still syncs to Apple Mail)
3. Fetches each message's raw content **once** and parses it into headers + body
4. Runs the detectors below, each producing evidence with a weight
5. Labels by severity and stars the message

It never trashes, never replies, never moves mail out of the inbox. Label and
star only.

## Detectors

| | Detector | Weight | What it looks for |
|---|---|---|---|
| **D1** | Brand near-miss (`Brands.gs`) | hard | Brand tokens with glued prefixes (`edocusign`), numeric suffixes (`docusign24`), separator splits (`docu-sign`), and typos within edit distance 2. Compares the brand's domain against **both** the From domain and the DKIM `d=` domain. |
| **D2** | Display-name obfuscation (`DisplayName.gs`) | scored | Names over 60 characters (the real address never renders on a phone), pseudo-directory syntax (`EN=`, `LAN=`), an embedded address on a different domain, long opaque identifier runs. |
| **D3** | Received-chain injection (`Provenance.gs`) | hard, **on** | Submission into a provider SMTP relay from a host unrelated to the sending domain. This is the compromised-tenant pattern. |
| **D4** | MUA fingerprint (`Fingerprint.gs`) | scored | `text/html` with no `multipart/alternative`, no `X-Mailer` and no `User-Agent`, a Message-ID host matching neither the sender nor a known generator, composition in the small hours of the sender's own stated timezone. |
| **D5** | Link analysis (`Links.gs`) | hard | A bare script at the web root of an unrelated host (`/dc.php`), links unrelated to both the claimed brand and the sender, your address encoded into the URL of an unrelated host, anchor text disagreeing with the href. **Parse only — never fetches.** |

Plus the v1 checks, unchanged: abused sending platforms (`firebaseapp.com`),
platform DKIM selectors on custom domains (Firebase's `firebase1`), owner-domain
self-impersonation, and the generic domain-in-display-name mismatch.

D6 (first-contact correlation against Sent) is **not implemented** — it costs a
Gmail search per message and is the weakest signal on its own.

### Scoring

Hard detectors weigh 100 and flag on their own — that is v1's behaviour, kept
deliberately. Scored detectors (D2, D4) are capped at 45 each, below the
threshold of 50, so no amount of display-name weirdness flags a message by
itself; weirdness **plus** a scripted-mailer fingerprint does.

Every verdict carries its full evidence list into the log and the alert email. A
bare score is not actionable — the reasoning chain is what tells you whether a
catch is real, and which detector to tune when it is not.

| Score | Label |
|---|---|
| 150+ | `SPOOF-1-CRITICAL` |
| 100–149 | `SPOOF-2-HIGH` |
| 50–99 | `SPOOF-3-WATCH` |

**Severity is carried by the number and the word, never by colour.** No Gmail
label colours are set at all. The maintainer is red/green colourblind, and a
severity tier you have to distinguish by hue is a severity tier you cannot read.

v1's single `SPOOF-ALERT` label is no longer applied. It is left in place so
previously flagged mail stays findable.

## What it catches

| Display name | Actual sender | Result |
|---|---|---|
| "Wіх.соm" (Cyrillic і and о) | info@bistro-pub.de | **Spoof detected** |
| "PаyPаl Security" (Cyrillic а) | alerts@some-random.com | **Spoof detected** |
| "Docs@theroadtlv" (your own org) | documents@asecureltd.com | **Spoof detected** |
| "eDocuSign Signature \| …/EN=RECIPIENTS/LAN=B7A7…" | office@sabeng.it, **SPF+DKIM+DMARC all pass** | **Spoof detected** (D1, D2, D3, D4, D5) |
| "Wix.com" | noreply@wix.com | Legitimate |
| "DocuSign NA3 System" | dse_na3@docusign.net | Legitimate |

That fourth row is the message v2 exists for, and it is fixture #1 in the test
suite. It is asserted to be caught by D1, D3, D4 and D5 **independently**, so no
single detector is load-bearing.

## False positives

This runs against a working inbox that receives a lot of legitimately relayed
mail. A tool that cries wolf on a newsletter gets muted, and then it catches
nothing. Two things keep that from happening:

- **D3's relay allowlist ships empty, and stays empty until measurement says
  otherwise.** A guessed entry is worse than none: it permanently exempts a
  domain + relay pair an attacker can then use freely. Before adding anything,
  measure:

  1. Run `reportRelayPairs()`. It prints every sender + relay pair currently in
     your mail, marks which ones D3 would flag, and changes nothing.
  2. `addRelayPair('example.com', 'smtp-relay.gmail.com')` for each pair you
     recognize as legitimate. Additions persist in Script Properties.

  A flagged pair is as likely to be the attack as a newsletter, so
  `reportRelayPairs()` deliberately will not hand you a ready-to-paste
  `addRelayPair()` call for one — you have to recognize the sender yourself.

  On the maintainer's own mailbox that measurement returned **one** pair across
  97 messages, and it was the phishing message, so D3 ships **enabled** with an
  empty allowlist. If your mail mixes differently, run the measurement before
  trusting that default. `ENABLE_RECEIVED_CHAIN` in `Provenance.gs`.

The sender whitelist from v1 still works: `addToWhitelist('example.com')`,
`removeFromWhitelist(...)`, `showWhitelist()`.

## Links are never fetched

`Links.gs` parses. It does not fetch, and there is no flag that makes it fetch.
A request would come from your own Google identity and IP — it confirms your
address is live and fingerprints the person investigating, which is exactly what
many phishing kits cloak on. The test suite fails the build if `UrlFetchApp`
appears anywhere in that file.

Every URL that reaches a log, an alert email or a debug report is defanged
(`hxxps://`, `[.]`) — including URLs inside subjects and display names. An alert
about a phishing message must not itself be one.

### Optional IP enrichment

ASN/geo lookup of the submission IP is **deliberately not implemented**.
Referencing `UrlFetchApp` anywhere in the project makes Apps Script request the
`script.external_request` OAuth scope from every installer, including everyone
who leaves the feature off. If you want it: set `ENABLE_IP_ENRICHMENT = true` in
`Provenance.gs`, add your lookup call inside `checkReceivedChain_`, and
re-authorize. The contract is that it sends **the IP and nothing else** — never
message content, subject lines, addresses or body text.

## Installation

### Option A: Copy-paste

1. Go to [script.google.com](https://script.google.com) and create a new project
2. Delete the default `Code.gs` content
3. Create these files (using the **+** button next to "Files"):
   `Code.gs`, `Homoglyphs.gs`, `Headers.gs`, `Brands.gs`, `DisplayName.gs`,
   `Fingerprint.gs`, `Links.gs`, `Provenance.gs`, `SpoofDetector.gs`, `Cache.gs`
4. Copy the contents of each `.gs` file from this repo into the corresponding file
5. Replace the contents of `appsscript.json` (gear icon → "Show appsscript.json
   manifest file in editor")

### Option B: clasp

```bash
npm install -g @google/clasp
clasp login
clasp create --type standalone --title "Unspoofer"
clasp push
```

### Activate

1. Select `testDetection` from the function dropdown and click **Run**
2. Authorize the requested Gmail permissions
3. Check the Execution log — all 59 test cases should show PASS
4. Select `setup` and click **Run**
5. Verify the three **SPOOF-*** labels appear in Gmail

## Testing

`testDetection()` runs in the Apps Script editor, and also locally with no
editor and no Google account:

```bash
node test-local.js        # failures only
node test-local.js -v     # every case with its evidence list
```

The `.gs` files are plain JavaScript. `test-local.js` concatenates them into one
`vm` script with the Apps Script globals stubbed, and exits non-zero on failure.
Every detector has at least one positive and one negative fixture, and the
negatives are drawn from real legitimate mail — a genuine DocuSign envelope, a
Substack send, a WordPress password reset, a Netlify form notification.

## Files

| File | Purpose |
|---|---|
| `Code.gs` | Entry points: `setup()`, `scanInbox()`, `uninstall()`, `testDetection()`, diagnostics |
| `Headers.gs` | Raw message parsing, header unfolding, auth-result extraction |
| `Homoglyphs.gs` | Unicode homoglyph map and `normalizeToAscii()` |
| `Brands.gs` | Brand domains, exact matching, and D1 near-miss matching |
| `DisplayName.gs` | D2 — display-name obfuscation |
| `Fingerprint.gs` | D4 — MUA fingerprint consistency |
| `Links.gs` | D5 — link analysis and defanging. Parse only. |
| `Provenance.gs` | D3 — Received-chain injection point, and the relay allowlist |
| `SpoofDetector.gs` | Sender parsing, domain extraction, the detector chain, scoring |
| `Cache.gs` | Processed message ID tracking (rolling 10K window) |
| `test-local.js` | Local test runner (Node, no Apps Script editor) |
| `appsscript.json` | Apps Script manifest |

## Diagnostics

| Function | What it does |
|---|---|
| `rescanInbox()` | Clears the processed cache and re-scans — run after deploying detection changes |
| `debugDkim()` | Logs and emails every step of DKIM detection over recent mail |
| `debugMessage()` | Full raw-header diagnostics for one specific sender |
| `reportRelayPairs()` | Lists sender + relay pairs in recent mail, for building the D3 allowlist |

## Uninstall

Run `uninstall()`. Removes all triggers and clears the message cache. The
severity labels are preserved so you can review previously flagged messages.

## Edge cases

- **Subdomains**: `mail.wix.com` is recognized as legitimate wix.com
- **Compound TLDs**: `.co.il`, `.co.uk`, `.com.au` handled
- **Short brand names**: length gates on D1 — affix matching needs a 6-character
  brand, edit-distance matching needs 8. Without them "groups" matches `ups` and
  "notice" matches `notion`.
- **English suffixes**: D1 is deliberately asymmetric. Characters *before* a
  brand are always deceptive; characters *after* it only count when they contain
  a digit. A symmetric rule matched 23 of 55 ordinary display names in a sweep —
  Squares Bakery, Amazonia Travel, Cloudflared Tunnel — because that is how
  English forms plurals and participles.
- **Execution limits**: stops scanning before the 6-minute Apps Script timeout
- **Quota**: 10-minute trigger = ~144 runs/day

## Apple Mail compatibility

Labels appear as folders under your Gmail account. Starred messages show as
flagged.

## License

MIT
