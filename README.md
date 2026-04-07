# Unspoofer — Gmail Display-Name Spoof Detector

If you run Gsuite as your email server, this is for you.

A Google Apps Script that automatically detects phishing emails that use **display-name spoofing** — where the sender name shows a trusted brand (e.g., "Wіх.соm" with Cyrillic characters) but the actual email comes from an unrelated domain (e.g., `info@bistro-pub.de`).

## How it works

1. Runs every 15 minutes via a time-driven trigger
2. Scans your recent inbox messages
3. Normalizes Unicode homoglyphs (Cyrillic, Greek, fullwidth characters) in sender display names
4. Checks normalized names against a curated list of ~50 brand domains
5. Compares the implied brand domain against the actual sender domain
6. Flags mismatches with a **SPOOF-ALERT** label and a star

## What it catches

| Display name | Actual sender | Result |
|---|---|---|
| "Wіх.соm" (Cyrillic і and о) | info@bistro-pub.de | **Spoof detected** |
| "PаyPаl Security" (Cyrillic а) | alerts@some-random.com | **Spoof detected** |
| "Wix.com" | noreply@wix.com | Legitimate |
| "Google" | no-reply@accounts.google.com | Legitimate |

## Installation

### Option A: Copy-paste (simplest)

1. Go to [script.google.com](https://script.google.com) and create a new project
2. Delete the default `Code.gs` content
3. Create 5 files (using the **+** button next to "Files") with these exact names:
   - `Code.gs`
   - `Homoglyphs.gs`
   - `Brands.gs`
   - `SpoofDetector.gs`
   - `Cache.gs`
4. Copy the contents of each `.gs` file from this repo into the corresponding file
5. Replace the contents of `appsscript.json` (click the gear icon > "Show appsscript.json manifest file in editor")

### Option B: Using clasp

```bash
npm install -g @google/clasp
clasp login
clasp create --type standalone --title "Unspoofer"
clasp push
```

### Activate

1. In the Apps Script editor, select `testDetection` from the function dropdown and click **Run**
2. Authorize the requested Gmail permissions when prompted
3. Check the Execution log — all 9 test cases should show PASS
4. Select `setup` from the dropdown and click **Run**
5. Verify the **SPOOF-ALERT** label appears in your Gmail

The scanner is now active and runs every 15 minutes.

## Files

| File | Purpose |
|---|---|
| `Code.gs` | Entry points: `setup()`, `scanInbox()`, `uninstall()`, `testDetection()` |
| `Homoglyphs.gs` | Unicode homoglyph map (~80 chars) and `normalizeToAscii()` |
| `Brands.gs` | ~50 brand domains and `findSpoofedBrand()` matching |
| `SpoofDetector.gs` | Sender parsing, root domain extraction, spoof detection logic |
| `Cache.gs` | Processed message ID tracking (rolling 10K window) |
| `appsscript.json` | Apps Script manifest with required OAuth scopes |

## Uninstall

Run `uninstall()` from the script editor. This removes all triggers and clears the message cache. The SPOOF-ALERT label is preserved so you can review previously flagged messages.

## How it handles edge cases

- **Subdomains**: `mail.wix.com` is recognized as legitimate wix.com
- **Compound TLDs**: `.co.il`, `.co.uk`, `.com.au` are handled correctly
- **Short brand names**: Brands shorter than 4 characters (like "x.com") require word-boundary matching to avoid false positives
- **Execution limits**: Stops scanning before the 6-minute Apps Script timeout
- **Quota limits**: 15-minute trigger = ~96 runs/day, within the 100/day trigger limit

## Apple Mail compatibility

Labels appear as folders under your Gmail account in Apple Mail. Starred messages show up as flagged.

## License

MIT
