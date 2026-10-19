# Secure Coding & Remediation Guide

This guide generalises the eight findings into reusable engineering controls. It is
written for a Node.js/Express + Angular stack but the principles are framework-agnostic.

## 1. Injection (SQL / NoSQL)

**Rule: data never becomes code.**

- Use parameterised queries / prepared statements exclusively. With Sequelize, use model
  methods or `replacements`; never interpolate user input into a query string.
  ```js
  // BAD
  db.query(`SELECT * FROM Users WHERE email='${email}'`);
  // GOOD
  db.query('SELECT * FROM Users WHERE email = ?', { replacements: [email] });
  ```
- Validate input against an allow-list of shape/type before it reaches the data layer.
- Apply least-privilege database accounts so an injection cannot read unrelated tables.

## 2. Broken Access Control (IDOR, privilege escalation)

**Rule: authenticate once, authorise every time, on the server.**

- On every request that touches an object, verify the authenticated principal is
  entitled to that specific object. Do not trust a client-supplied id as proof of
  ownership.
- Derive identity from the session where possible rather than from request parameters.
- Enforce role checks on the server for every privileged endpoint. Hiding a UI route is
  not access control.
- Default-deny: a new endpoint should require explicit authorisation, not inherit open
  access.

## 3. Session & Token Security (JWT)

- Sign tokens with a strong secret or private key kept only on the server and out of
  source control.
- Pin the algorithm server-side; reject tokens whose `alg` differs and never accept
  `none`.
- Validate `exp`, `iss`, `aud` on every request. Keep lifetimes short; support
  revocation for sensitive actions.

## 4. Cross-Site Scripting (XSS)

- Rely on the framework's output encoding (Angular auto-sanitises); never reach for
  `bypassSecurityTrustHtml` / `innerHTML` with untrusted data.
- Encode per context (HTML, attribute, JS, URL).
- Add a restrictive `Content-Security-Policy` as defence in depth.

## 5. Sensitive Data & File Exposure

- Serve only an explicit allow-list of public assets; keep backups, configs and data
  files out of the web root.
- Canonicalise paths before any security decision; reject null bytes and traversal
  sequences.
- Store secrets in a secrets manager or environment, never in the repository.

## 6. Security Misconfiguration

- Return generic errors to clients; log stack traces server-side only.
- Set security headers: `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Disable directory listing; remove unused routes and sample content.

## 7. Business Logic

- Enforce every invariant server-side: quantities positive and within stock/limits,
  prices and discounts computed server-side, coupons validated against issuance records.
- Never trust a value just because it came back from your own earlier response.

## 8. Process controls

- Make parameterised queries, server-side authorisation checks, and output encoding
  explicit items on the code-review checklist.
- Run SAST/DAST in CI and triage findings before release.
- Add regression tests that assert each fixed vulnerability stays fixed.
