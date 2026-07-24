# JwtAuth Plugin — Security Review

Scope: this plugin (controller, TokenService, CorsHelper, ApiAuth front-controller plugin, models, install SQL), plus the host site's Docker deploy config where it touches auth. Reviewed 2026-07-24.

## Summary

No SQL injection, no auth bypass, no algorithm-confusion issues found. Core token handling is sound (bcrypt verify, hashed refresh tokens at rest, `random_bytes(32)`, HS256 pinned via `Key`, role read fresh from DB not from JWT). Main gaps: **no refresh-token rotation revocation, no rate limiting, no password policy, weak committed dev secret**. Details below, ordered by severity.

---

## High

> **Status: all three High issues fixed** (plugin v0.2.0, 2026-07-24). See fix notes under each item.

### H1. Refresh tokens never revoked on rotation — stolen token valid 30 days
`TokenService::issue()` inserts a new refresh token but never revokes the old one (`AuthController::meAction`, `ApiAuth::preDispatch` silent refresh). Every refresh leaves the previous token live until natural expiry.

- Impact: an exfiltrated refresh token works for its full 30-day life even after the legitimate client rotates. Also defeats stolen-token detection (proper rotation lets you detect reuse of a superseded token and kill the whole session family).
- Fix: on silent refresh, revoke the presented token in the same transaction as issuing the new one. Optionally add `replaced_by` column; if a revoked token is presented, revoke all tokens for that user (reuse = theft signal).
- **Fixed**: `TokenService::rotate()` revokes the presented token before issuing the new pair; both silent-refresh sites (`meAction`, `ApiAuth::preDispatch`) use it. Reuse-detection (session-family kill) left as follow-up.

### H2. No rate limiting / brute-force protection
`POST /auth/login` and `POST /auth/register` accept unlimited attempts. No lockout, no delay, no captcha.

- Impact: credential stuffing / password brute force against known emails; mass fake-account registration (each register also writes a user row + token row).
- Fix: per-IP + per-account throttle (e.g. fail2ban on the JSON 401s, or an attempts table with exponential backoff). At minimum put a reverse-proxy rate limit on `/auth/*`.
- **Fixed**: `JwtAuth_RateLimiter` + `jwt_auth_attempts` table (added via install/upgrade hook). Login: 20 failures / 15 min per IP, 5 / 15 min per email (counter cleared on success). Register: 5 attempts / hour per IP. Over-limit → 429. IPs read without trusting `X-Forwarded-For`; rows older than 24 h purged opportunistically.

### H3. Weak JWT secret committed in the host site's `docker-compose.yml`
`JWT_SECRET: dev-secret-change-in-production-xx` is in the repo, and `TokenService::_secret()` falls back to this env var. Anyone with repo access can forge access tokens for any user/role if this compose file (or the same value) reaches production.

- Fix: production secret must come from a secrets store / untracked env file; ≥32 random bytes. Consider refusing to start (or logging loudly) if the secret equals the known dev value or is under 32 chars.
- **Fixed**: `TokenService::_secret()` now throws outside `APPLICATION_ENV=development` if the secret is under 32 chars or equals the known dev default. `docker-compose.yml` declares itself development (`APPLICATION_ENV: ${APPLICATION_ENV:-development}`) and takes `JWT_SECRET` from the environment; real deploys must set both.

---

## Medium

> **Status: M1–M3 fixed, M4 partially fixed** (2026-07-24). See fix notes under each item.

### M1. No password strength policy on register
`registerAction` only checks password non-empty. Omeka's `User::_validate()` validates username/name/email but **not** password (form-layer concern in core), and `setPassword()` hashes anything — so `"a"` is an accepted password. The plan called for min-length validation; it isn't implemented.

- Fix: enforce min length (≥8, per NIST) in `registerAction` before `save()`, return 422.
- **Fixed**: `PASSWORD_MIN_LENGTH = 8` enforced in `registerAction` → 422.

### M2. Deactivated user keeps working access token; logout doesn't kill access token
- `meAction` returns 200 from the JWT alone — no `active` check (`_userPayload` uses `find()`, not `findActiveById`). A deactivated user reads their profile for up to 15 min. (`ApiAuth` does use `findActiveById`, so `/api/*` is correctly gated.)
- Logout revokes the refresh token but the access JWT stays valid until `exp` — standard stateless-JWT tradeoff, but combined with the above it means "deactivate user" is not immediate anywhere the JWT alone is trusted.
- Fix: use `findActiveById` in `_userPayload` (also fixes L1); accept the 15-min window as documented tradeoff or add a small denylist keyed on `user_id + iat` for forced logout.
- **Fixed**: `_userPayload` now uses `findActiveById` and returns null → 401 for deactivated or deleted users (also fixes L1). The 15-min access-token validity after logout remains as the documented stateless-JWT tradeoff.

### M3. CSRF posture relies entirely on CORS preflight + JSON parsing
Cookies are `SameSite=None` in production (required for the cross-subdomain frontend), and there are no CSRF tokens. Protection today: browsers won't send `Content-Type: application/json` cross-site without a preflight, and the allowlist rejects foreign origins.

- Residual risk: `POST /auth/logout` and `/auth/login` execute fine from a cross-site HTML form (form-encoded body parses to `[]` → login 422, but logout succeeds) → logout CSRF (nuisance) and potential login-CSRF if body parsing ever accepts form data.
- Fix (cheap): reject requests whose `Content-Type` isn't `application/json` on all `/auth/*` POSTs; optionally check `Origin`/`Sec-Fetch-Site` server-side and 403 mismatches.
- **Fixed**: all `/auth/*` POSTs (login, logout, register) now require `Content-Type: application/json` → 415 otherwise. Cross-site HTML forms cannot send that header without a CORS preflight, which the origin allowlist rejects.

### M4. User enumeration
- `registerAction` returns "That email address has already been claimed." → direct oracle for which emails have accounts.
- `loginAction` returns early when the email doesn't exist, skipping `password_verify` → measurable timing difference (bcrypt ≈ 50–100 ms).
- Fix: register — send a neutral response (or accept + email-verify flow); login — run `password_verify` against a dummy hash when user not found.
- **Partially fixed**: login now runs `password_verify` against a dummy bcrypt hash when the email is unknown, equalizing response timing. Register still returns a distinct duplicate-email error — a truly neutral response needs an email-verification flow (no email infra yet); the 5/hour/IP register rate limit throttles enumeration in the meantime. Accepted risk, revisit with email verification.

---

## Low

> **Status: L1–L7 fixed** (2026-07-24); L8 accepted as documented legacy tradeoff.

### L1. 500 on deleted user with live token
`_userPayload()` doesn't null-check `find($userId)`; a user deleted while their JWT is valid → fatal on `$user->id`. Return 401 when lookup fails. (Fixed by the M2 change.)
- **Fixed** with M2.

### L2. Non-string JSON values cause 500s
`{"email": ["x"], "password": {"y":1}}` → `trim()`/`password_verify()` TypeError. Validate `is_string()` on email/password/name; return 422.
- **Fixed** in the high-priority PR (`is_string()` checks on all auth JSON fields).

### L3. Expired/revoked token rows never purged
`jwt_refresh_tokens` grows unbounded (a row per login *and* per silent refresh). Add a cron/hook purge of `expires_at < NOW()` and old revoked rows; index `user_id`.
- **Fixed**: `TokenService::issue()` opportunistically purges expired rows and revoked rows older than a 7-day grace window (kept briefly for future reuse-detection).

### L4. `iss` claim set but never verified
`validateAccessCookie` ignores `iss`. Verify it to stop tokens minted for another environment sharing the same secret from being accepted.
- **Fixed**: `iss` must equal `WEB_ROOT` or the token is rejected.

### L5. No `Cache-Control: no-store` on auth responses
Responses carrying user data + `Set-Cookie` should send `Cache-Control: no-store` to keep shared caches/proxies out.
- **Fixed**: all `/auth/*` responses send `Cache-Control: no-store`.

### L6. CORS allowlist is a hardcoded localhost TODO
`CorsHelper::_allowedOrigins()` returns only localhost origins. Not exploitable (fails closed), but production is blocked until fixed — implement the config-driven list and keep it exact-match (never reflect arbitrary origins while `Allow-Credentials: true`).
- **Fixed**: allowlist reads `jwtauth.allowed_origins` from Omeka config, falling back to the `JWT_ALLOWED_ORIGINS` env var (comma-separated), then to the localhost defaults. Still exact-match only; configuring the list disables the localhost defaults.

### L7. `Secure` flag depends on `APPLICATION_ENV`
If production ever runs with `APPLICATION_ENV=development` (copy-pasted config), cookies ship without `Secure` and with `SameSite=Lax`. Prefer detecting HTTPS (`$_SERVER['HTTPS']` / forwarded proto) or an explicit plugin config flag.
- **Fixed**: cookie flags now follow the actual request scheme — HTTPS (direct or via `X-Forwarded-Proto`) → `Secure; SameSite=None`; plain HTTP → `SameSite=Lax`, no `Secure`. `APPLICATION_ENV` no longer influences cookies.

### L8. Legacy `?key=` API auth retained
Pre-existing Omeka behavior (kept intentionally): keys in query strings end up in access logs and referrers. Restrict to server-to-server clients; consider disabling once the frontend fully migrates.

---

## Post-review discovery

### D1. `auth_token` cookie never reached the browser (fixed)
Found while verifying the low-priority fixes live: ZF1's `sendHeaders()` replays raw headers via PHP `header()` with replace=true, so the second `Set-Cookie` always overwrote the first — only `refresh_token` was ever delivered, and every request authenticated through silent refresh. Benign pre-rotation; after H1 it meant one rotation per request and a logout race under parallel requests.

- **Fixed**: cookies are emitted with `header('Set-Cookie: …', false)` on real requests (the only way PHP sends multiple same-name headers); the response-object path is kept for CLI/test inspection. Verified live: login sets both cookies, logout clears both.

## What's done right (verified)

- All DB access parameterized (`findByTokenHash`, `revokeByTokenHash`, `findByEmail`, `_generateUsername`) — no SQLi.
- Refresh tokens: 32 random bytes, stored only as SHA-256 hash — DB dump doesn't yield usable tokens.
- JWT decode pins HS256 via `Key` object (firebase/php-jwt v7) — no `alg=none`/confusion attacks.
- `ApiAuth` loads role/permissions fresh from DB (`findActiveById`) — JWT `role` claim never trusted, deactivated users can't hit `/api/*`.
- Register ignores client-supplied `role`/`username` fields — no mass assignment; role fixed to `contributor` and the model's role-permission check isn't bypassable via this path.
- Login: generic "Invalid credentials" for wrong-password vs wrong-email (message-level), `active` checked, `password_verify` (bcrypt).
- Cookies `HttpOnly` everywhere; XSS can't read tokens.
- CORS: exact-match origin allowlist with credentials — no wildcard reflection.
- Errors return JSON, no stack traces or internals leaked.

## Recommended fix order

1. H3 — secret hygiene before any deploy (config change, zero code).
2. H1 — rotation revocation (small, contained in `TokenService`).
3. M1, L1, L2 — input/validation hardening in `AuthController` (one small PR).
4. H2, M3 — rate limiting + Content-Type check (infra + a few lines).
5. M2, M4, L3–L7 — as follow-ups.

---

## Test results (2026-07-24, all fixes deployed)

All fixes landed via three merged PRs (plugin repo: #6 high, #7 medium, #8 low + D1), each verified three ways.

### PHPUnit suite

**42 tests, 104 assertions, 0 failures** — 17 of them added by this hardening work (`tests/SecurityTest.php`, plus updates to `LogoutMeTest.php`). Coverage per finding:

- H1: silent refresh revokes the presented token; a rotated-away token is refused (401)
- H2: 6th failed login per email → 429; counter cleared on success; 6th register per IP → 429
- H3: secrets under 32 chars and the known dev default both throw outside development
- M1: 6-char password → 422, no user row created
- M2/L1: deactivated user and deleted user with a still-valid token → 401 (no 500)
- M3: form-encoded login → 415; form-encoded logout → 415 and the refresh token is *not* revoked
- L3: expired row and 8-day-old revoked row purged on issue; fresh row survives
- L4: valid-signature token with a foreign `iss` → 401
- L5: login response carries `Cache-Control: no-store`
- L6: `JWT_ALLOWED_ORIGINS` origin allowed; localhost defaults disabled once configured
- L7: HTTP → `SameSite=Lax`, no `Secure`; HTTPS → `Secure; SameSite=None`

### Live API checks (curl against the rebuilt stack)

- Valid login → 200 with user JSON; **both** `auth_token` and `refresh_token` cookies delivered (D1 confirmed fixed)
- 5 bad passwords → 401 ×5, 6th attempt → 429
- Form-encoded login → 415
- 3-char register password → 422 "Password must be at least 8 characters."
- `Cache-Control: no-store` present on auth responses
- Logout → 204, both cookies cleared with `Max-Age=-1`

### Browser end-to-end (React frontend at localhost:5173)

- Anonymous load → login button, no account UI
- Login → nav shows user, account section with role + admin link
- Page refresh → session restored via `/auth/me` 200 (served by the access cookie, no rotation burned)
- Logout → server 204, UI anonymous; refresh after logout stays anonymous (cookies genuinely cleared server-side)

*(One tooling artifact: the browser extension's network panel showed the logout POST as 503; the Apache access log records 204 and the post-refresh state confirms it.)*

### Outstanding

- M4 (register email enumeration) — accepted risk until an email-verification flow exists; throttled at 5/hour/IP
- L8 (legacy `?key=` in URLs) — accepted legacy tradeoff
- H1 follow-up idea: reuse-detection (revoke the whole session family when a superseded token is presented)
