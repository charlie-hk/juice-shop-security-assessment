# Executive Summary

## Engagement

A time-boxed web-application penetration test was performed against a locally hosted
instance of **OWASP Juice Shop**, an intentionally vulnerable application published by
OWASP for security training. The assessment followed the OWASP Web Security Testing
Guide (WSTG v4.2) and rated findings with CVSS v3.1.

The goal was to identify, exploit and document realistic web-application weaknesses, and
to produce remediation guidance a development team could act on. This is a lab exercise
against a self-owned target; the structure and rigour mirror a real engagement.

## Results at a glance

**8 findings** were confirmed across authentication, authorization, session management,
input validation, configuration and business logic.

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 3 |
| Medium | 4 |
| Low | 0 |

## Key risks

- **Authentication bypass via SQL injection (Critical).** The login endpoint can be
  bypassed entirely with a crafted email value, granting administrator access without
  credentials. This single flaw compromises the whole application.
- **Broken access control (High).** Users can read and alter other users' data (baskets)
  by changing an identifier, and reach administrative functionality not intended for them.
- **Cross-site scripting (High).** Unencoded rendering of user input allows script
  execution in victims' sessions, including stored variants affecting many users.
- **Sensitive data in the session token (Medium).** The JWT payload carries the user's
  role, email and password hash in cleartext; combined with the XSS above, a stolen
  token hands an attacker that data directly.

## Overall assessment

The application is exploitable end-to-end: an unauthenticated attacker can reach
administrator access, read other customers' data, and execute script in their browsers.
In production terms this is a critical-risk posture. Every finding has a well-understood,
standard remediation — primarily parameterised queries, server-side authorisation on every
object and endpoint, strict token validation, and context-aware output encoding.

## Recommended priorities

1. Eliminate SQL injection by moving all database access to parameterised queries.
2. Enforce object- and function-level authorisation server-side on every request.
3. Harden JWT validation (pinned algorithm, strong secret, full claim checks).
4. Apply context-aware output encoding and a restrictive CSP.
5. Remove exposed backup/config files and add security response headers.
