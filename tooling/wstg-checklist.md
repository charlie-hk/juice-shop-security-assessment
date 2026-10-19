# OWASP WSTG Coverage Checklist

Coverage of the areas exercised in this assessment, mapped to WSTG v4.2. `✓` = tested
and documented, `~` = reviewed, no notable finding, `—` = out of scope for this lab.

## Information Gathering (WSTG-INFO)
- [✓] INFO-02 Fingerprint web server / framework
- [✓] INFO-05 Review webpage content for information leakage
- [~] INFO-08 Fingerprint web application frameworks

## Configuration & Deployment (WSTG-CONF)
- [✓] CONF-02 Test application platform configuration (errors/headers) → JS-07
- [✓] CONF-04 Review old, backup and unreferenced files → JS-06
- [~] CONF-05 Enumerate admin interfaces → see JS-03
- [✓] CONF-07 Test HTTP strict transport security

## Authentication (WSTG-ATHN)
- [✓] ATHN-04 Testing for bypassing authentication schema → JS-01
- [~] ATHN-07 Testing for weak password policy

## Authorization (WSTG-ATHZ)
- [✓] ATHZ-02 Testing for bypassing authorization schema → JS-03
- [✓] ATHZ-04 Testing for insecure direct object references → JS-02

## Session Management (WSTG-SESS)
- [✓] SESS token structure & validation (JWT) → JS-04
- [~] SESS-02 Testing for cookie attributes

## Input Validation (WSTG-INPV)
- [✓] INPV-01/02 Testing for reflected/stored XSS → JS-05
- [✓] INPV-05 Testing for SQL injection → JS-01

## Error Handling (WSTG-ERRH)
- [✓] ERRH-01 Testing for improper error handling → JS-07

## Cryptography (WSTG-CRYP)
- [~] CRYP-03 Testing for sensitive information sent via unencrypted channels
- [~] CRYP weak storage review

## Business Logic (WSTG-BUSL)
- [✓] BUSL-01/02 Business logic data validation → JS-08

## Client-side (WSTG-CLNT)
- [✓] CLNT-01 DOM-based XSS → JS-05
- [—] CLNT-11 Local storage / sensitive data (noted for follow-up)
