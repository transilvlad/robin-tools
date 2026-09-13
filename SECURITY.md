# Security Policy

## Supported versions

Robin Tools does not currently publish formal versioned releases beyond git
tags. Security fixes are applied to the `main` branch and released as the
current `latest` state of the project. If you are running an older tag or a
fork, please update to the current `main` before reporting an issue, if
practical, so we can confirm whether it is already fixed.

## Reporting a vulnerability

Please report security vulnerabilities privately rather than opening a public
GitHub issue. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this
repository, including:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof of concept
- The affected file(s), endpoint(s), or component(s), if known
- Any suggested remediation, if you have one

We ask that you give us a reasonable opportunity to investigate and address a
report before any public disclosure (coordinated disclosure). There is no bug
bounty program associated with this project.

## What to expect

- Acknowledgment of your report within 5 business days.
- An initial assessment (severity and next steps) within 14 days of
  acknowledgment.
- Notification when a fix is merged to `main`, and credit in the fix's commit
  or release notes if you would like it.

## Scope and areas of particular interest

Robin Tools is a mail-diagnostics module (DNS/SPF/DMARC/DKIM/MTA-STS/TLS-RPT/
DANE/BIMI checks, RBL/DBL blocklist lookups, raw-message analysis, and
SMTP/IMAP/POP3 port probing) that can run in two modes:

- **Module mode**: a backend service reached only through an authenticated
  proxy in the sibling [Robin Admin](https://github.com/transilvlad/robin-admin)
  project, using a shared `MODULE_PROXY_SECRET`.
- **Standalone mode**: a self-contained deployment with its own bundled
  PostgreSQL database and single-user login (HTTP Basic Auth, or no auth for
  trusted/offline use only). See the "Deployment modes" section of the
  [README](README.md).

Reports involving any of the following are especially welcome:

- Server-side request forgery (SSRF) via any outbound DNS/HTTP(S)/SMTP/IMAP/
  POP3 target this module resolves or connects to, including redirect
  handling and the private/public address validation in
  `server/src/services/network-safety.ts`
- Bypassing the module-proxy authentication (`x-robin-module-secret`), the
  standalone-mode HTTP Basic Auth, or the viewer/editor/admin role checks in
  `server/src/middleware/`
- Resource exhaustion via the blocklist, bulk-check, or message-analysis
  endpoints (target/input-size limits, rate limiting)
- Injection (SQL, DNS query-name, or command injection)

Thank you for helping keep Robin Tools and its operators safe.
