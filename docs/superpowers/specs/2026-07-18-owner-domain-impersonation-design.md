# Owner-Domain Impersonation Detection — Design

Date: 2026-07-18
Status: Approved, ready for implementation planning

## Problem

A phishing email reached the inbox undetected by unspoofer:

```
Display name:  Docs@theroadtlv          (the recipient's own org, styled as an internal mailbox)
Actual sender: documents@asecureltd.com (external attacker-controlled domain)
Return-Path:   documents@asecureltd.com
```

The message passed SPF, DKIM, and DMARC because `asecureltd.com` is a genuinely
registered, attacker-controlled Google Workspace domain (DKIM
`d=asecureltd-com.20251104.gappssmtp.com`, sent via `smtp-relay.gmail.com`).
Authentication is not forged and therefore cannot catch this — the lie is that
an **external sender is wearing the recipient's own organizational identity** in
the From display name.

This is display-name spoofing, the exact class unspoofer targets. It slipped
through for two specific reasons in `SpoofDetector.gs`:

1. **`extractDomainFromDisplayName()` requires a dotted TLD** (regex at
   `SpoofDetector.gs:188` matches `word.tld`). The display name `Docs@theroadtlv`
   has no `.com` and is `@`-styled, so the function returns `null`, the generic
   mismatch check at step 5b never runs, and the message is cleared.

2. **The owner-domain exception actively suppresses this case.**
   `SpoofDetector.gs:257-258` (commit `70ea0f4`) skips any message whose display
   name implies the owner's own domain, on the assumption that "phishing
   impersonates other brands, not your own domain to you." This email is the
   counterexample. That exception was added to stop false positives on legitimate
   form-service notifications (e.g. `"theroadtlv.com" <formresponses@netlify.com>`),
   which carry the full owner domain *with* TLD.

The discriminator: the legit form-service case uses the full domain **with** TLD
(`theroadtlv.com`); the attack drops the TLD and `@`-styles the bare org label
(`Docs@theroadtlv`) to mimic an internal mailbox.

## Goal

Flag an external sender that references the recipient's own organizational
identity in the From display name — whether bare (`theroadtlv`), `@`-styled
(`Docs@theroadtlv`), or full-domain (`theroadtlv.com`) — while preserving the
legitimate on-behalf-of service notifications that exception `70ea0f4` protects.

Non-goal: matching spaced or reworded variants of the org name (e.g.
"The Road TLV"). See Limitations.

## Design (Approach C: invariant + known-service carve-out)

### The invariant

The recipient's own organizational identity appearing in the From display name,
when the message is not actually from the recipient's own aligned domain, is
impersonation — independent of whether a TLD is present.

### New check: `checkOwnerImpersonation()`

Runs as a dedicated, high-confidence step in `checkForSpoof()`, after the
suspicious-platform / DKIM-selector checks and before the brand-list checks.

```
ownerRoot  = getOwnerDomain_()          // e.g. "theroadtlv.com"
if !ownerRoot: return null
ownerToken = ownerRoot.split('.')[0]    // "theroadtlv"
if ownerToken.length < 4: return null   // too short to word-match safely

normalized = normalizeToAscii(displayName).toLowerCase()   // homoglyph-safe

references = normalized contains ownerRoot (full domain)
             OR  /\b<ownerToken>\b/ matches normalized       // bare or @-styled

if !references: return null

senderRoot = extractRootDomain(sender.email domain)
if senderRoot === ownerRoot: return null                     // genuinely internal
if OWNER_REF_ALLOWED_SERVICES includes senderRoot: return null   // legit on-behalf-of
// (sender whitelist is already checked upstream in checkForSpoof)

return SPOOF {
  brand:   ownerToken,
  reason:  "Display name impersonates your own domain (" + ownerToken +
           ") but email is from " + senderRoot,
  details: "From: " + from + " | Owner: " + ownerRoot + " | Actual: " + senderRoot,
}
```

The `\b<ownerToken>\b` word-boundary match catches all three attack forms in one
expression, because `@` and `.` are non-word characters that satisfy `\b`:
`Docs@theroadtlv`, `theroadtlv`, and `theroadtlv.com`. The display name is
homoglyph-normalized via the existing `normalizeToAscii()` first, so Cyrillic /
Greek / fullwidth lookalikes cannot bypass it.

The `ownerToken.length < 4` guard mirrors the existing short-brand handling
(README "How it handles edge cases") and prevents a short owner label from
matching common words.

### The carve-out

A small, global allowlist of services legitimately allowed to name the owner's
org, keyed on the **actual authenticated sender root domain**. Because these
messages pass SPF/DKIM for those real domains, the sender root cannot be forged,
so the carve-out cannot be abused by a lookalike.

```
const OWNER_REF_ALLOWED_SERVICES = [
  'netlify.com',
  'formspree.io',
  'google.com',
  'docusign.net',
];
```

`"theroadtlv.com" <formresponses@netlify.com>` passes (netlify.com is allowed);
the same display name from `asecureltd.com` is flagged.

### Interaction with the existing generic check (keep lines 257-258)

`checkOwnerImpersonation()` runs *before* the brand and generic checks and is the
single authority on owner-domain references: it either flags the message or
intentionally passes it (internal sender / carve-out). The existing owner-skip at
`SpoofDetector.gs:257-258` must therefore be **kept**, not removed. It now serves
as a defer-to-upstream guard: when the generic check at step 5b sees a display
name implying the owner domain, it returns without flagging, because
`checkOwnerImpersonation()` already ruled on it.

Removing lines 257-258 would regress the carve-out: for
`"theroadtlv.com" <formresponses@netlify.com>`, `checkOwnerImpersonation()` passes
it, but the generic check would then see `impliedRoot (theroadtlv.com) ≠
actualRoot (netlify.com)` and re-flag it. Keeping the guard prevents that
double-flag. Attacks never reach step 5b — they are flagged upstream by
`checkOwnerImpersonation()`.

### Verdict & label

Reuse the existing **SPOOF-ALERT** label and star. This is a spoof; reusing the
label keeps the surface simple. Only the `reason` / `details` strings differ, so
owner-impersonation is distinguishable on review. (A distinct label/severity for
self-impersonation is a possible future addition, deliberately out of scope now.)

## Changes by file

- **`SpoofDetector.gs`**
  - Add `OWNER_REF_ALLOWED_SERVICES` const.
  - Add `checkOwnerImpersonation(sender, from)` function.
  - Wire it into `checkForSpoof()` as a dedicated step after the DKIM-selector
    check (step ~3c), returning early on a hit.
  - Keep the owner-domain skip at lines 257-258 (now a defer-to-upstream guard;
    see "Interaction with the existing generic check").
- **`Code.gs`** — add the test cases below to `testDetection()`.
- **`README.md`** — document self-impersonation detection under "What it catches".
- **`CHANGELOG.md`** — add an entry.

## Tests

Added to `testDetection()` (owner domain overridden per-case, as the existing
harness already supports):

| From | Owner | Expect | Why |
|---|---|---|---|
| `"Docs@theroadtlv" <documents@asecureltd.com>` | theroadtlv.com | spoof | the reported attack |
| `"theroadtlv.com" <documents@asecureltd.com>` | theroadtlv.com | spoof | closes the with-TLD variant |
| `"Docs@theroadtlv.com" <documents@asecureltd.com>` | theroadtlv.com | spoof | @-styled with TLD |
| `"theroadtlv.com" <formresponses@netlify.com>` | theroadtlv.com | pass | carve-out (known service) |
| `"theroadtlv Team" <admin@theroadtlv.com>` | theroadtlv.com | pass | genuinely internal sender |

All existing test cases must still pass. In particular
`"someoneelse.com" <formresponses@netlify.com>` (owner theroadtlv.com) stays a
spoof: `someoneelse.com` is not the owner, so `checkOwnerImpersonation()` does not
fire and it is caught by the existing generic display-name check.

## Limitations (documented, accepted)

- Matches the org **label** as a single token; spaced or reworded variants
  ("The Road TLV") are not detected. Fuzzy matching would raise false-positive
  risk and is out of scope.
- The carve-out list needs occasional upkeep as on-behalf-of services change.
- Owner tokens shorter than 4 characters are not matched (guard against
  false positives on short domains).
