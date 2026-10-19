# Methodology

## Standard

This assessment follows the **OWASP Web Security Testing Guide (WSTG) v4.2** as its
testing framework, with severity ratings derived from **CVSS v3.1** base scores. The
engagement is structured along the PTES phases (pre-engagement, intelligence gathering,
threat modelling, vulnerability analysis, exploitation, reporting).

## Target

| Item | Value |
|------|-------|
| Application | OWASP Juice Shop |
| Nature | Intentionally vulnerable web application, published by OWASP for security education |
| Version tested | 17.x (self-hosted locally) |
| Stack | Node.js / Express backend, Angular single-page frontend, SQLite (via Sequelize), REST API |
| Deployment | Local instance (`docker run -p 3000:3000 bkimminich/juice-shop`) |
| Authorisation | Self-owned local instance; OWASP explicitly licenses the application for security testing and training |

> **Scope note.** This is a lab assessment against a deliberately vulnerable training
> application running on infrastructure owned by the tester. No third-party or production
> system was touched. The methodology, tooling and reporting format mirror a real
> engagement so the work is representative of professional practice.

## Phases

1. **Reconnaissance & mapping.** Enumerate routes, API endpoints, client-side bundles,
   and technology fingerprints. Build a request map in the proxy.
2. **Configuration & deployment testing** (WSTG-CONF). Review exposed files, error
   handling, HTTP headers, and administrative surfaces.
3. **Authentication testing** (WSTG-ATHN). Test the login flow, credential policy,
   and account-recovery logic.
4. **Authorization testing** (WSTG-ATHZ). Test for broken access control, IDOR, and
   privilege escalation.
5. **Session management** (WSTG-SESS). Inspect token issuance, structure, and validation.
6. **Input validation** (WSTG-INPV). Test for injection (SQLi, NoSQLi) and cross-site
   scripting (reflected, stored, DOM).
7. **Cryptography** (WSTG-CRYP). Review storage of secrets and sensitive data at rest.
8. **Business logic** (WSTG-BUSL). Test workflows for logic that can be abused.
9. **Reporting.** Each finding is documented with a WSTG reference, CVSS vector,
   impact, reproduction steps, evidence, and remediation guidance.

## Tooling

| Tool | Use |
|------|-----|
| Burp Suite Community | Intercepting proxy, request tampering, repeater |
| OWASP ZAP | Passive scanning, spidering |
| Browser DevTools | Network/Application inspection, DOM analysis |
| `jwt_tool` / jwt.io | JSON Web Token inspection and tampering |
| `sqlmap` (confirmation only) | Confirming injection points found manually |
| `curl` / `httpie` | Scripted request replay |

## Severity model

Severity is the CVSS v3.1 base score, banded as:

| Band | Score |
|------|-------|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| Informational | 0.0 |
