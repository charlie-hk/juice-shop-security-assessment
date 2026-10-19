# Detailed Findings

Each finding lists its WSTG reference, CVSS v3.1 vector and score, affected component,
impact, reproduction steps, evidence, and remediation. All testing was performed against
a locally hosted instance at `http://localhost:3000`.

---

## JS-01 — SQL Injection in login allows authentication bypass

| | |
|---|---|
| **Severity** | Critical (9.8) |
| **WSTG** | WSTG-INPV-05 (SQL Injection), WSTG-ATHN-04 |
| **CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Component** | `POST /rest/user/login` |

### Description
The login endpoint builds its SQL query by concatenating the user-supplied `email`
field directly into the statement. A crafted value terminates the intended predicate
and comments out the password check, authenticating as the first matching row — the
administrator.

### Reproduction
1. Browse to the login page and open the intercepting proxy.
2. Submit the login form with:
   - **Email:** `' OR 1=1--`
   - **Password:** any value
3. The request body sent is:
   ```json
   { "email": "' OR 1=1--", "password": "x" }
   ```
4. The response returns `200 OK` with a valid authentication token and the admin
   user object. The session is now authenticated as `admin@juice-sh.op`.

To target a specific account instead of the first row:
`' OR email='admin@juice-sh.op'--`

### Impact
Full authentication bypass and account takeover of any user, including the
administrator, without credentials. This is the highest-impact class of web flaw:
it compromises confidentiality, integrity and availability simultaneously.

### Remediation
- Use parameterised queries / prepared statements for every database call. With
  Sequelize, pass values through `replacements` or model methods, never string
  concatenation.
- Treat the ORM as the only path to the database; forbid raw concatenated SQL in
  code review.
- Add a WAF rule as defence in depth, not as the primary control.

---

## JS-02 — Broken access control: horizontal IDOR on baskets

| | |
|---|---|
| **Severity** | High (8.1) |
| **WSTG** | WSTG-ATHZ-04 (IDOR) |
| **CVSS v3.1** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Component** | `GET /rest/basket/{id}` |

### Description
The basket endpoint authorises by authentication alone, not by ownership. An
authenticated user can read and modify another user's basket by changing the numeric
`id` in the path; the server never checks that the basket belongs to the caller.

### Reproduction
1. Register and log in as a normal user. Note your own basket id from
   `GET /rest/basket/{yourId}`.
2. Replay the request with a different id, e.g. `GET /rest/basket/1`.
3. The response returns another user's basket contents (products, quantities).

### Impact
Disclosure and manipulation of other customers' basket data. In a real shop this
leaks purchasing data and enables tampering with other users' orders.

### Remediation
- Enforce object-level authorisation on every request: confirm the authenticated
  principal owns (or is explicitly entitled to) the requested object before returning it.
- Prefer server-derived identity (the basket tied to the session) over client-supplied
  ids where possible.
- Consider non-sequential, unguessable identifiers (defence in depth, not a substitute
  for authorisation checks).

---

## JS-03 — Privilege escalation to administration panel

| | |
|---|---|
| **Severity** | High (8.8) |
| **WSTG** | WSTG-ATHZ-02 (Bypassing authorization schema) |
| **CVSS v3.1** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` |
| **Component** | Angular route `#/administration`, backing admin APIs |

### Description
The administration section is hidden in the UI but not enforced server-side for all of
its data. The client route can be reached directly, and the backing endpoints return
privileged data (user list, feedback) without a server-side role check robust enough to
stop a crafted token or direct API call.

### Reproduction
1. Authenticate as any user.
2. Navigate directly to `http://localhost:3000/#/administration`.
3. Observe the registered-user listing (emails) and feedback management surface load.

### Impact
Exposure of the full customer email list and administrative functionality to
non-administrators.

### Remediation
- Enforce authorisation on the server for every administrative endpoint, keyed on a
  trusted role claim validated server-side.
- Never rely on hiding a client-side route for access control; the SPA bundle is fully
  visible to the client.

---

## JS-04 — Forgeable JWT: unsigned/known-key token accepted

| | |
|---|---|
| **Severity** | High (8.1) |
| **WSTG** | WSTG-SESS-related; WSTG-ATHN |
| **CVSS v3.1** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Component** | JWT issuance/validation (`Authorization: Bearer`) |

### Description
Session tokens are JWTs whose signing material and algorithm handling are weak. The
token payload (including the user identity/role) can be altered and re-presented in
ways the server accepts, because algorithm and signature validation are not strictly
enforced (e.g. `alg` confusion / known key).

### Reproduction
1. Capture the `Authorization: Bearer <jwt>` header after logging in.
2. Decode the JWT at jwt.io or with `jwt_tool`. Observe the user object in the payload.
3. Modify the payload (e.g. change the email/role), re-sign under the weak/known key or
   abuse the algorithm handling, and replay the request.
4. The server honours the forged identity.

### Impact
Identity spoofing and privilege escalation via token tampering, independent of the
login flow.

### Remediation
- Use a strong, secret signing key held only on the server; rotate it and keep it out
  of source control.
- Pin the expected algorithm server-side (e.g. RS256) and reject any token whose `alg`
  differs; never accept `none`.
- Keep token lifetimes short and validate all standard claims (`exp`, `iss`, `aud`).

---

## JS-05 — Stored/DOM Cross-Site Scripting

| | |
|---|---|
| **Severity** | High (7.2) |
| **WSTG** | WSTG-INPV-01/02 (Reflected/Stored XSS), client DOM sinks |
| **CVSS v3.1** | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| **Component** | Search field and selected input fields rendered without encoding |

### Description
User input is rendered into the page through a sink that does not encode HTML, allowing
script execution in the context of other users' sessions. Depending on the field, the
payload is reflected (search) or persisted (stored), the latter being more severe.

### Reproduction
1. In an injectable field, submit a payload such as:
   `<iframe src="javascript:alert(\`xss\`)">`
2. Observe the script executing when the input is rendered.
3. For stored variants, confirm the payload fires for a second user viewing the same data.

### Impact
Execution of attacker-controlled script in victims' browsers: session-token theft,
action-on-behalf-of-user, UI redressing. Stored XSS can affect every viewer of the
poisoned data.

### Remediation
- Context-aware output encoding at every sink; rely on Angular's built-in sanitisation
  and avoid `bypassSecurityTrust*`.
- Validate and normalise input server-side.
- Deploy a restrictive Content-Security-Policy as defence in depth.

---

## JS-06 — Sensitive data exposure: readable backups and config

| | |
|---|---|
| **Severity** | Medium (6.5) |
| **WSTG** | WSTG-CONF-04 (Review old/backup/unreferenced files), WSTG-ATHZ-01 |
| **CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Component** | `/ftp` directory and static file serving |

### Description
A static directory exposes backup, configuration and data files that should not be
web-reachable. Access-control relies on an extension filter that can be bypassed with
path/encoding tricks (e.g. Poison Null Byte, double extensions).

### Reproduction
1. Browse to `http://localhost:3000/ftp`.
2. Enumerate the listed files; download those directly served.
3. For files behind the extension filter, apply the documented bypass (e.g.
   `...coupons_2013.md.bak%2500.md`) to retrieve them.

### Impact
Disclosure of coupon logic, internal documents and configuration, aiding further attacks.

### Remediation
- Do not expose backup/data directories over HTTP; serve only an explicit allow-list of
  public assets.
- Remove unreferenced and backup files from the web root entirely.
- Normalise and canonicalise paths before any filter decision; reject null bytes.

---

## JS-07 — Security misconfiguration: verbose errors & missing headers

| | |
|---|---|
| **Severity** | Medium (5.3) |
| **WSTG** | WSTG-CONF-02 / WSTG-ERRH (Error handling), WSTG-CONF-07 |
| **CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Component** | Global error handler, HTTP response headers |

### Description
Error responses can return stack traces and framework details, disclosing internal
structure. Security-relevant response headers (CSP, HSTS, X-Content-Type-Options,
etc.) are absent or weak.

### Reproduction
1. Send malformed input to an API endpoint (e.g. a bad type to a typed field).
2. Observe the verbose error / stack trace in the response.
3. Inspect response headers for missing CSP/HSTS/X-Content-Type-Options.

### Impact
Information disclosure that accelerates targeted attacks, and weaker in-browser defences.

### Remediation
- Return generic error messages to clients; log details server-side only.
- Add `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options:
  nosniff`, and a sensible `Referrer-Policy`.

---

## JS-08 — Business logic: negative/invalid quantities & coupon abuse

| | |
|---|---|
| **Severity** | Medium (5.3) |
| **WSTG** | WSTG-BUSL-01/02 (Business logic data validation) |
| **CVSS v3.1** | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Component** | Basket/checkout quantity handling, coupon validation |

### Description
Workflow fields are trusted beyond their intended range. Quantities and coupon/discount
logic can be manipulated to reach states the business did not intend (e.g. non-positive
quantities, reused or crafted discounts).

### Reproduction
1. Add an item to the basket, intercept the update request, and set `quantity` to a
   negative or otherwise invalid value.
2. Observe the server accepting the state and the effect on the order total.

### Impact
Financial manipulation of orders; integrity loss in the purchasing workflow.

### Remediation
- Enforce server-side invariants on every business field (quantity > 0, within stock,
  within per-order limits).
- Validate coupons server-side against issuance records, expiry, and single-use rules.

---

## Summary table

| ID | Finding | WSTG | Severity | CVSS |
|----|---------|------|----------|------|
| JS-01 | SQLi auth bypass | INPV-05 / ATHN-04 | Critical | 9.8 |
| JS-02 | IDOR on baskets | ATHZ-04 | High | 8.1 |
| JS-03 | Admin panel privilege escalation | ATHZ-02 | High | 8.8 |
| JS-04 | Forgeable JWT | ATHN / SESS | High | 8.1 |
| JS-05 | Stored/DOM XSS | INPV-01/02 | High | 7.2 |
| JS-06 | Exposed backup/config files | CONF-04 | Medium | 6.5 |
| JS-07 | Misconfig: errors & headers | CONF-02 / ERRH | Medium | 5.3 |
| JS-08 | Business logic abuse | BUSL-01/02 | Medium | 5.3 |
