# Proposal: Multi-User / Admin Deployment

<img src="images/mascot.png" align="right" width="160" alt="Unspoofer mascot">

## Background

Unspoofer is a Google Apps Script that detects display-name spoofing in
Gmail (e.g., "Wіх.соm" written with Cyrillic characters from a non-Wix
domain). Today it is a per-user install: each user copies the script
into their own Apps Script project and authorizes Gmail access individually.

- Repo: <https://github.com/yoelf22/unspoofer>
- Architecture: 6-file Apps Script project, per-user OAuth, 15-min
  time-driven trigger, ~50 brand domains hardcoded in `Brands.gs`.

## The Goal

Adapt Unspoofer for a Google Workspace organization with one admin and
multiple end users. The admin should be able to:

1. Deploy the scanner to all users in an OU without each user manually
   copying code.
2. Maintain the brand list and allowlist centrally.
3. See a consolidated view of detections across all monitored mailboxes.

End users should:

- Get spoofed-message labeling automatically.
- Need minimal (or zero) interaction beyond initial OAuth consent.

## Proposed Approaches (alternatives welcome)

**Option A — Workspace Marketplace add-on**
- Republish the Apps Script as a private Workspace add-on.
- Admin force-installs it for an OU via the Admin Console.
- Each user still authorizes their own Gmail (per-user OAuth).
- Shared brand list + allowlist live in a Sheet the admin owns.
- Detections pipe to a central "SpoofAlerts" Sheet for admin visibility.

**Option B — Centralized service-account scanner**
- One GCP project with a service account using domain-wide delegation.
- Backend (Cloud Run / Cloud Functions, Node or Python) scans every
  mailbox from one cron.
- No per-user install; instant rollout to new hires.
- Larger security surface; requires admin DwD approval.

Rough fit: Option A for orgs under ~50 users, Option B above that.
Contributors may take on one, the other, or both.

## Deliverables

- Source code in this repo (MIT).
- Admin install/setup guide.
- End-user docs (or "you don't need to do anything" if fully transparent).
- Brand list + allowlist editing workflow for the admin.
- Aggregated reporting view (Sheet, dashboard, or web UI).
- Tests covering the spoof-detection logic — existing `testDetection()`
  pattern is fine to extend.

## Acceptance Criteria

- Admin can deploy to a test OU of N users in under 30 minutes.
- A new brand added to the central list propagates to all scanners
  within one trigger cycle.
- Admin can view all detections from one place.
- The existing per-user install path remains functional and documented.
- All existing `testDetection()` cases continue to pass.

## Constraints

- Must work with Google Workspace (any tier that supports Marketplace
  add-ons or domain-wide delegation).
- Apps Script for Option A; contributor's choice of stack for Option B.
- License: MIT.
- Code style: match existing repo (vanilla JS, no transpiler on the
  Apps Script side).

## Out of Scope

- Spoofing types other than display-name homoglyph mismatches
  (lookalike domains, reply-to mismatches, SPF/DKIM/DMARC validation).
- Outbound mail scanning.
- Non-Google Workspace providers (M365, Fastmail, etc.).
- ML/AI-based detection.

## How to Contribute

This is an open source effort — MIT licensed, no compensation, full
credit and maintainer status for substantial contributions.

If you're interested, comment on the discussion:
<https://github.com/yoelf22/unspoofer/discussions/1>

Useful background for picking up this work:

- Apps Script + Gmail API basics
- Google Workspace Marketplace add-on publishing flow (for Option A)
- GCP service accounts with domain-wide delegation (for Option B)

Open questions and design discussion welcome before any code is written.
