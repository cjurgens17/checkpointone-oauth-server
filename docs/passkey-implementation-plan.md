# Passkey (WebAuthn) Implementation Plan

Decisions already locked in:

- **Challenge storage:** Redis, via the existing `utility/redis/cache.py` helpers.
- **RP ID:** the server's own origin (`http://localhost:5000` in dev).
- **Authentication style:** discoverable credentials (resident keys) — no username required to start login.
- **Enrollment gating:** a user can only register a passkey *after* authenticating some other way (password or social) in the current session. There is no registration path for an unauthenticated visitor.

References below are to the W3C Web Authentication spec (Level 2/3): §5.4 (`PublicKeyCredentialCreationOptions`), §5.5 (`PublicKeyCredentialRequestOptions`), §7.1 (Registering a New Credential), §7.2 (Verifying an Authentication Assertion), §13.1 (Cryptographic Challenges).

---

## 1. Redis challenge issuance & storage

- [ ] **Generate challenges correctly.** Per §13.1, a challenge must come from a CSPRNG and should be at least 16 bytes of entropy. Use `secrets.token_bytes(32)` — same approach already used by `generate_passkey_user_handle()` in `services/passkey.py`.
- [ ] **Pick a key namespace.** `create_auth_code()` in `services/tokens/authorization_code.py` uses the token itself as the Redis key. Do the same here, but prefix so registration/authentication challenges can't collide with each other or with auth-code entries in the same Redis DB (e.g. `passkey_reg:<challenge>`, `passkey_auth:<challenge>`).
- [ ] **Decide what rides along with the challenge.**
  - Registration: you already know the user (session is authenticated) — store `user_id` alongside the challenge so verify-time can confirm the ceremony belongs to the same user who requested it.
  - Authentication (discoverable): you do *not* know the user yet — the payload can only be the challenge itself plus whatever expected-origin/RP ID context you want to double check at verify time.
- [ ] **Write `create_registration_challenge(user)` and `create_authentication_challenge()`** in `services/passkey.py`, modeled directly on `create_auth_code()`: generate bytes, base64url-encode for JSON transport to the browser, `cache_set(key, payload, ttl)`.
- [ ] **Pick a TTL.** The ceremony is a single uninterrupted user gesture (browser prompt → biometric/PIN → done), so keep it short — 60–120s is typical. Whatever you choose, pass a matching `timeout` value in the options sent to the browser so the UI doesn't outlive the server-side challenge.
- [ ] **Write the redeem function** mirroring `redeem_auth_code()`: `cache_get` immediately followed by `cache_delete`, *regardless* of whether verification later succeeds — this is what makes the challenge single-use and closes the replay window.
- [ ] **Write the comparison helper.** Decode `clientDataJSON.challenge` (base64url) from the browser's response and compare it against the redeemed value using a constant-time comparison (`hmac.compare_digest`), not `==`.

---

## 2. Registration (enrollment) endpoints

### 2a. Options endpoint — builds `PublicKeyCredentialCreationOptions` (§5.4)

- [ ] Require an authenticated session (reuse `is_valid_session` / `get_session_from_session_id` — same gate the enrollment prompt itself sits behind).
- [ ] If `User.user_handle` is `NULL`, generate it now via `generate_passkey_user_handle()` and persist it. This must happen exactly once per user, ever — every subsequent passkey they register reuses the same handle.
- [ ] Build the options payload:
  - `rp`: `{ id: <RP ID>, name: <app/tenant name> }`
  - `user`: `{ id: <base64url user_handle>, name: <username/email>, displayName: <name> }`
  - `challenge`: from `create_registration_challenge(user)`, base64url-encoded
  - `pubKeyCredParams`: at minimum `[{ type: "public-key", alg: -7 }]` (ES256); consider adding `-257` (RS256) for older Windows Hello devices
  - `authenticatorSelection.residentKey: "required"` (discoverable, per your decision), `userVerification` (decide `"preferred"` vs `"required"`)
  - `excludeCredentials`: the user's existing `credential_id`s, so the same authenticator can't be registered twice
  - `attestation: "none"` — no attestation trust chain needed for this use case, keeps things simpler and more private
- [ ] Return the JSON options to the browser for `navigator.credentials.create()`.

### 2b. Verify endpoint — implements §7.1 registration verification

- [ ] Require the same authenticated session as the options call.
- [ ] Redeem the stored challenge; reject if missing/expired.
- [ ] Parse `clientDataJSON` (base64url → JSON): check `type == "webauthn.create"`, `challenge` matches the redeemed value, `origin` matches your expected origin exactly.
- [ ] Parse `attestationObject` (CBOR) into `fmt`, `authData`, `attStmt`.
- [ ] Parse `authData`: verify `rpIdHash == SHA-256(RP ID)`; check flags — `UP` (user present) must be set, `UV` (user verified) set if required; note the `BE`/`BS` bits, they map to `backed_up`/`device_type`.
- [ ] Extract `attestedCredentialData` from `authData`: `aaguid`, `credentialId`, `credentialPublicKey` (COSE-encoded).
- [ ] Since `attestation: "none"` was requested, there's no attestation statement trust chain to validate — skip that step.
- [ ] Insert the `Passkey` row: `user_id`, `credential_id`, `public_key` (COSE bytes), `sign_count` (from `authData`), `aaguid`, `device_type`/`backed_up` (from flags), `transports` (from the client's reported `response.transports`).
- [ ] Return success; this is the point where the enrollment-prompt flow continues on to the existing `_issue_auth_code` call, same as password login does today.

---

## 3. Discoverable authentication (login) endpoints

### 3a. Options endpoint — builds `PublicKeyCredentialRequestOptions` (§5.5)

- [ ] No session or username required — this is the point of discoverable credentials.
- [ ] Build the options payload: `rpId`, `challenge` (from `create_authentication_challenge()`), `allowCredentials: []` (empty/omitted — this is what makes it discoverable), `userVerification`, `timeout`.
- [ ] Return JSON for `navigator.credentials.get()`.

### 3b. Verify endpoint — implements §7.2 assertion verification

- [ ] Redeem the stored challenge; reject if missing/expired.
- [ ] Parse `clientDataJSON`: check `type == "webauthn.get"`, challenge matches, origin matches.
- [ ] Look up `Passkey` by `credential_id` (the response's `rawId`) — reject if none found.
- [ ] Parse `authenticatorData`: verify `rpIdHash`, check `UP`/`UV` flags, extract `signCount`.
- [ ] Compare `userHandle` from the response against the `user_handle` of the `User` resolved via `Passkey.user_id` — reject on mismatch (this is the cross-check from earlier).
- [ ] Verify the signature: it must validate over `authenticatorData || SHA-256(clientDataJSON)` using the stored `public_key` (COSE-decoded). This is the actual cryptographic proof of possession.
- [ ] Check `signCount`: new value must be greater than the stored value, unless both are `0` (some authenticators never increment it — treat that as "not supported," don't reject). A same-or-lower non-zero count is a possible cloned authenticator — decide the reject/flag policy here.
- [ ] On success: update `Passkey.sign_count` and `last_used_at`, resolve the `User`, and call the existing `_issue_auth_code` path — same endpoint password/social login already uses.

---

## Open decisions to revisit

- **Hand-roll vs. library.** Nothing in `requirements.txt` currently handles CBOR/COSE parsing or WebAuthn signature verification. Doing this by hand (attestation object parsing, COSE key decoding, signature verification) is a lot of security-sensitive surface area to get exactly right. Worth evaluating a library (e.g. `webauthn` (duo-labs/py_webauthn) or `fido2` (Yubico's python-fido2)) before writing this from scratch.
- **`userVerification` requirement** — `"preferred"` vs `"required"` for both registration and authentication options.
- **Where the endpoints live** — `resources/passkey.py` (JSON API, matching `resources/token.py`'s Flask-RESTful style) vs. `views/passkey.py` (Blueprint style, matching `authorize.py`). The repo currently has both patterns; pick one for consistency.
- **`sign_count` regression policy** — reject outright vs. flag and log (mentioned above, not yet decided).
