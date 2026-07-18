# Owner-Domain Impersonation Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flag an external sender that wears the inbox owner's own organizational identity in the From display name (e.g. `"Docs@theroadtlv" <documents@asecureltd.com>`), while preserving legitimate on-behalf-of service notifications.

**Architecture:** Add a dedicated, high-confidence `checkOwnerImpersonation()` step to `checkForSpoof()` in `SpoofDetector.gs`, running after the platform/DKIM checks and before the brand checks. It matches the owner's org label (whole word, homoglyph-normalized) against the display name and flags when the actual sender is external and not on a small known-services allowlist. The existing owner-domain skip at `SpoofDetector.gs:257-258` is kept as a defer-to-upstream guard.

**Tech Stack:** Google Apps Script (`.gs` files are plain ES; no build step, no external dependencies). Tests live in `Code.gs`'s `testDetection()` and are exercised by a local Node runner during development.

## Global Constraints

- `.gs` files are plain JavaScript run by Apps Script — no `require`/`import`, no npm dependencies, no external network calls in detection code.
- Match the surrounding code style: JSDoc on functions, `const`/`let`, no TypeScript.
- Detection functions must be pure over their inputs (owner domain comes from the module-level cache, which the test harness overrides) — do not read live Gmail/Session state inside the new check.
- Owner org label is the first DNS label of the owner root domain; only match it when it is ≥ 4 characters (mirrors the existing short-brand guard).
- The known-services allowlist is keyed on the **actual authenticated sender root domain**, never on display-name content.
- Reuse the existing SPOOF-ALERT verdict shape `{isSpoof, reason, brand, details}`; no new label.

**Reference spec:** `docs/superpowers/specs/2026-07-18-owner-domain-impersonation-design.md`

---

## File Structure

- `SpoofDetector.gs` — add `OWNER_REF_ALLOWED_SERVICES` const + `checkOwnerImpersonation()` function; wire into `checkForSpoof()`; keep lines 257-258.
- `Code.gs` — add four test cases to `testDetection()`.
- `README.md`, `CHANGELOG.md` — document the new detection.
- `<scratchpad>/run-tests.js` — local Node runner (NOT committed; dev-only verification).

---

## Task 1: Local test runner (dev tooling)

A Node harness that loads the `.gs` files and runs `testDetection()`, so TDD is executable without the Apps Script editor. Not committed — it lives in the scratchpad.

**Files:**
- Create: `/private/tmp/claude-501/-Users-yoel-Projects-code-email-tools-unspoofer/e9bc040a-7b19-40b0-be6b-3c49d8c19835/scratchpad/run-tests.js`

**Interfaces:**
- Consumes: the repo's `Homoglyphs.gs`, `Brands.gs`, `SpoofDetector.gs`, `Code.gs` (their `testDetection()` and `checkForSpoof()`).
- Produces: a CLI that prints the `testDetection()` Logger output and exits 0 when "0 failed", 1 otherwise.

- [ ] **Step 1: Write the runner**

Concatenate all four `.gs` files into a single VM script so top-level `const`/`let`/`function` declarations share one lexical scope (`_ownerDomainCache` is a module-level `let` that `testDetection()` reassigns — separate `vm` scripts would not share it).

```javascript
// Local dev runner for unspoofer's testDetection(). Not part of the shipped project.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const repo = '/Users/yoel/Projects/code/email-tools/unspoofer';
const files = ['Homoglyphs.gs', 'Brands.gs', 'SpoofDetector.gs', 'Code.gs'];

const logs = [];
const sandbox = {
  Logger: { log: (m) => logs.push(String(m)) },
  PropertiesService: { getScriptProperties: () => ({ getProperty: () => null }) },
  Session: {
    getEffectiveUser: () => ({ getEmail: () => '' }),
    getActiveUser: () => ({ getEmail: () => '' }),
  },
  GmailApp: {},
  console,
};
vm.createContext(sandbox);

const combined =
  files.map((f) => fs.readFileSync(path.join(repo, f), 'utf8')).join('\n;\n') +
  '\ntestDetection();';
vm.runInContext(combined, sandbox, { filename: 'combined.gs' });

const out = logs.join('\n');
console.log(out);
const m = out.match(/Results: (\d+) passed, (\d+) failed/);
if (m && m[2] === '0') {
  console.log('\nALL PASS');
  process.exit(0);
}
console.log('\nFAILURES PRESENT');
process.exit(1);
```

- [ ] **Step 2: Run the runner against the current (unmodified) code**

Run: `node "/private/tmp/claude-501/-Users-yoel-Projects-code-email-tools-unspoofer/e9bc040a-7b19-40b0-be6b-3c49d8c19835/scratchpad/run-tests.js"`
Expected: prints per-case PASS lines and ends with `Results: N passed, 0 failed` then `ALL PASS` (exit 0). This confirms the runner faithfully reproduces the existing suite before any changes.

- [ ] **Step 3: No commit** — the runner is scratchpad-only dev tooling and must not be committed.

---

## Task 2: Owner-impersonation detection (TDD)

**Files:**
- Modify: `Code.gs` (add cases inside `testDetection()`'s `testCases` array, before the closing `];`)
- Modify: `SpoofDetector.gs` (add const + function; wire into `checkForSpoof()`)
- Test: run via the Task 1 runner

**Interfaces:**
- Consumes: `getOwnerDomain_()` → `string` (owner root domain), `normalizeToAscii(string)` → `string`, `extractRootDomain(string)` → `string`, `parseSender(string)` → `{displayName, email}`.
- Produces: `checkOwnerImpersonation(sender, from)` where `sender` is `{displayName: string, email: string}` and `from` is the raw From string; returns `{isSpoof: true, reason: string, brand: string, details: string}` on a hit, or `null` otherwise. Also `const OWNER_REF_ALLOWED_SERVICES: string[]`.

- [ ] **Step 1: Write the failing tests**

In `Code.gs`, inside `testDetection()`, insert these four cases immediately after the existing case named `'Form-service notification still flagged when not your own domain'` and before the array's closing `];`:

```javascript
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
      name: 'Owner label from the owner\'s own domain — legitimate internal sender',
      from: '"theroadtlv Team" <admin@theroadtlv.com>',
      expectSpoof: false,
      ownerDomain: 'theroadtlv.com',
    },
```

(The carve-out case `"theroadtlv.com" <formresponses@netlify.com>` is already present in the suite as `'Form-service notification: display name = recipient own domain'` — do not duplicate it.)

- [ ] **Step 2: Run tests to verify the attack cases fail**

Run: `node "/private/tmp/claude-501/-Users-yoel-Projects-code-email-tools-unspoofer/e9bc040a-7b19-40b0-be6b-3c49d8c19835/scratchpad/run-tests.js"`
Expected: `FAILURES PRESENT` (exit 1). The three `expectSpoof: true` owner-impersonation cases show `Detected as spoof: false (expected: true)`. The internal-sender case already passes (no detection yet). This confirms the tests exercise the gap.

- [ ] **Step 3: Add the allowlist constant**

In `SpoofDetector.gs`, immediately after the `SUSPICIOUS_DKIM_SELECTORS` const block (ends around line 23), add:

```javascript
/**
 * Root domains of services legitimately allowed to put the recipient's own
 * organization name/domain in the From display name (form-service and
 * on-behalf-of notifications, e.g. Netlify Forms, DocuSign). Keyed on the
 * actual authenticated sender root, which SPF/DKIM guarantee — so this
 * carve-out cannot be abused by a lookalike sender.
 */
const OWNER_REF_ALLOWED_SERVICES = [
  'netlify.com',
  'formspree.io',
  'google.com',
  'docusign.net',
];
```

- [ ] **Step 4: Add the `checkOwnerImpersonation()` function**

In `SpoofDetector.gs`, add this function immediately before `function checkForSpoof(message) {` (around line 199):

```javascript
/**
 * Detects an external sender wearing the inbox owner's own organizational
 * identity in the From display name — internal-impersonation phishing such as
 * "Docs@theroadtlv" <documents@asecureltd.com>.
 *
 * The owner's org label (e.g. "theroadtlv" from "theroadtlv.com") is matched as
 * a whole word after homoglyph normalization, so it fires on the bare token,
 * the @-styled form, and the full domain alike (@ and . are non-word characters,
 * so the \b boundaries hold). The message passes when the sender is the owner's
 * own aligned domain (genuinely internal) or a recognized on-behalf-of service.
 *
 * This check is authoritative for owner-domain references: it either flags the
 * message or intentionally clears it. The generic check at step 5b defers to it
 * via the kept owner-domain skip.
 *
 * @param {{displayName: string, email: string}} sender - parsed From
 * @param {string} from - raw From header string (for details)
 * @returns {{isSpoof: boolean, reason: string, brand: string, details: string}|null}
 */
function checkOwnerImpersonation(sender, from) {
  const ownerRoot = getOwnerDomain_();
  if (!ownerRoot) return null;

  const ownerToken = ownerRoot.split('.')[0];
  if (ownerToken.length < 4) return null; // too short to word-match safely

  if (!sender.displayName) return null;
  const normalized = normalizeToAscii(sender.displayName).toLowerCase();

  // Owner org labels contain only [a-z0-9-], none of which are regex
  // metacharacters, so the token is safe to embed directly.
  const tokenPattern = new RegExp('\\b' + ownerToken + '\\b');
  const references =
    tokenPattern.test(normalized) || normalized.indexOf(ownerRoot) !== -1;
  if (!references) return null;

  const senderDomain = sender.email.split('@')[1];
  if (!senderDomain) return null;
  const senderRoot = extractRootDomain(senderDomain);

  if (senderRoot === ownerRoot) return null; // genuinely internal
  if (OWNER_REF_ALLOWED_SERVICES.indexOf(senderRoot) !== -1) return null; // legit on-behalf-of

  return {
    isSpoof: true,
    brand: ownerToken,
    reason: 'Display name impersonates your own domain (' + ownerToken +
      ') but email is from ' + senderRoot,
    details: 'From: ' + from + ' | Owner: ' + ownerRoot + ' | Actual: ' + senderRoot,
  };
}
```

- [ ] **Step 5: Wire the check into `checkForSpoof()`**

In `SpoofDetector.gs`, inside `checkForSpoof()`, insert the new step between the DKIM-selector block and the `// 4. Normalize display name` comment. Locate this existing text:

```javascript
  // 4. Normalize display name and look for brand match
```

and insert immediately **before** it:

```javascript
  // 3c. Check for owner-domain impersonation: an external sender wearing the
  //     inbox owner's own org identity in the display name (e.g.
  //     "Docs@theroadtlv" <documents@asecureltd.com>). Authoritative for
  //     owner-domain references — the generic check at step 5b defers to it.
  const ownerSpoof = checkOwnerImpersonation(sender, from);
  if (ownerSpoof) return ownerSpoof;

```

(`sender` and `from` are already in scope: `from = message.getFrom()` and `sender = parseSender(from)` earlier in the function. Do NOT remove the owner-domain skip at lines 257-258 — it now prevents the generic check from re-flagging carve-out senders.)

- [ ] **Step 6: Run tests to verify all pass**

Run: `node "/private/tmp/claude-501/-Users-yoel-Projects-code-email-tools-unspoofer/e9bc040a-7b19-40b0-be6b-3c49d8c19835/scratchpad/run-tests.js"`
Expected: `Results: N passed, 0 failed` then `ALL PASS` (exit 0). All four new cases pass, the existing carve-out and "someoneelse.com" cases stay green, and every prior case is unchanged.

- [ ] **Step 7: Commit**

```bash
git add SpoofDetector.gs Code.gs
git commit -m "Detect owner-domain impersonation in From display name

Flags an external sender wearing the inbox owner's own org identity
(bare label, @-styled, or full domain), e.g.
\"Docs@theroadtlv\" <documents@asecureltd.com>, which passed SPF/DKIM
and slipped through the existing display-name checks. Adds
checkOwnerImpersonation() with a known on-behalf-of service allowlist
so legitimate form/e-sign notifications still pass.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Documentation

**Files:**
- Modify: `README.md` (the "What it catches" section)
- Modify: `CHANGELOG.md` (new entry at the top of the change list)

**Interfaces:**
- Consumes: nothing. Produces: nothing (docs only).

- [ ] **Step 1: Update the README "What it catches" table**

In `README.md`, locate the table under `## What it catches` and add a row after the `"PаyPаl Security"` row and before the `"Wix.com"` row:

```markdown
| "Docs@theroadtlv" (your own org) | documents@asecureltd.com | **Spoof detected** |
```

Then add this sentence immediately below the table (after the closing table row, before the `## Installation` heading):

```markdown
It also catches **self-impersonation**: an external sender wearing your own organization's name or domain in the display name — bare (`theroadtlv`), `@`-styled (`Docs@theroadtlv`), or full-domain (`theroadtlv.com`). Recognized on-behalf-of services (Netlify, Formspree, Google, DocuSign) that legitimately name your org are allowed through.
```

- [ ] **Step 2: Add a CHANGELOG entry**

In `CHANGELOG.md`, add a new entry at the top of the list of changes (match the existing file's format — check the top of the file and mirror its heading/date style):

```markdown
- Detect owner-domain (self) impersonation: flag external senders that put your
  own organization's name/domain in the From display name, e.g.
  "Docs@theroadtlv" <documents@asecureltd.com>. Includes an allowlist of
  recognized on-behalf-of services so legitimate form/e-sign mail still passes.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "Document owner-domain impersonation detection

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review Notes

- **Spec coverage:** detection rule → Task 2 Steps 3-5; carve-out → allowlist in Step 3 + logic in Step 4; keep-257-258 → Step 5 note; verdict/label reuse → Step 4 return shape; tests → Task 2 Step 1 (four new) plus existing carve-out case; docs + limitations → Task 3.
- **Placeholder scan:** all code shown in full; no TBD/TODO.
- **Type consistency:** `checkOwnerImpersonation(sender, from)` signature and `{isSpoof, reason, brand, details}` return shape are consistent between the interface block, the function body, and the `checkForSpoof()` wiring.
