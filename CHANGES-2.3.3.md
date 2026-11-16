# Wander Installer 2.3.3 (unreleased)

Fixes Apple ID sign-in failing since about 2026-10-12 with -80045 ("This action cannot be
completed at this time") at the first sign-in request, and -80046 at the token step since
2026-10-22. The cause: Apple now rejects anisette (the device-identity headers) produced by
Android-ADI-backed servers when the client claims to be a Mac, and Wander's default server
(ani.846969.xyz) and every other old preset is Android-backed.

isideload stays at 0.2.22 (vendored under `src-tauri/vendor/isideload`). The upstream fixes
below are backported into that layout, not taken by upgrading to 0.5.x, because 0.5.x needs
idevice 0.1.68, which broke the pairing stack before.

Nothing here was tested against Apple's servers. The four new servers were checked with one
GET of `/v3/client_info` each on 2026-11-15; all four report
`<MacBookPro13,3> <Mac OS X;10.12.6;16G29> ... (com.apple.akd/1.0)`.

## 1. Mac-backed anisette servers, new default, store-key migration

Mirrors nab138/iloader cc5b168 (store-key rename), 9025975 and 9797eca (server list).

- `src/anisette.ts` (new): the preset list is now `mac-ani.jkcoxson.com` (default),
  `ani.iloader.app`, `new.ani.sidestore.io` and `ani3.stikstore.app`. The Android-backed
  servers are removed.
- The persisted store key is renamed from `anisetteServer` to `anisetteServerMac1`, so a
  2.3.2 install moves to the new default instead of keeping its old server.
- One exception, as asked: a user's own Custom server is carried over to the new key once,
  unless it is on the known-bad list (`KNOWN_BAD_ANISETTE_SERVERS`: every pre-2.3.3 preset,
  including ani.stikstore.app, plus ani.npeg.us). Upstream drops every old value.
- `src/StoreContext.tsx`: calls `readInitialStoreValues` (in `src/anisette.ts`), which runs
  `migrateAnisetteServerKey` once, after the store is loaded and before any value is read.
  A failed migration is logged and does not block start-up.
- `src/pages/Settings.tsx`, `src/AppleID.tsx`, `src/ErrorContext.tsx`,
  `src/components/OperationView.tsx`: use the shared key, default and list.
- `src-tauri/vendor/isideload/src/anisette/remote_v3/mod.rs`: the library's own
  `DEFAULT_ANISETTE_V3_URL` is now `https://mac-ani.jkcoxson.com`. Wander always passes the
  URL explicitly, so this is only a safety net.
- Test: `tests/anisette.test.ts` (run with `bun test tests/`). It hard-codes the eight 2.3.2
  presets from dd16173 `src/pages/Settings.tsx`, so dropping one from the bad list fails, and
  it checks that start-up migrates before reading.
- Deliberate difference from upstream, kept as the task asked: a legacy Custom server that is
  not on the known-bad list survives the migration. A self-hosted anisette-v3-server (the stock
  image runs Android CoreADI) or an unlisted Android-backed public server will therefore keep
  failing with -80045/-80046. Those errors now show the `anisette_rejected` advice (section 5),
  which tells the user to pick another server.

## 2. Re-provision anisette when the server changes or anyone answers -45061

Mirrors nab138/isideload 8ca39b6. The "server changed" check is Wander's own addition.

- `src-tauri/vendor/isideload/src/anisette/mod.rs`: providers now return
  `AnisetteDataResponse` (`Data`, `NeedsProvisioning` or `IncorrectlyProvisioned`).
  `AnisetteDataGenerator` provisions as needed, with at most `MAX_ANISETTE_ATTEMPTS` = 3
  provider round trips per call. This is upstream's budget, and it covers the worst case:
  load from storage, then the server answers -45061, then a fresh provision. On
  `IncorrectlyProvisioned` it discards the cached state (`provision(gs, force_reset = true)`).
  `needs_provisioning()` is removed from the trait, as upstream did. When the budget runs
  out it raises the typed `SideloadError::AnisetteProvisioningExhausted` (new in
  `vendor/isideload/src/lib.rs`), so the app classifies it without matching message text.
- `src-tauri/vendor/isideload/src/anisette/remote_v3/mod.rs`:
  - A `/v3/get_headers` error whose message contains `-45061` now maps to
    `IncorrectlyProvisioned` instead of failing the sign-in (pure function
    `headers_to_response`).
  - The provisioned state is saved together with a new `anisette_state_url` key that
    records which server it belongs to (`save_state`). Stored state is reused only when that
    marker matches the configured server (`select_state`). State saved by 2.3.2 has no
    marker, so every existing install provisions fresh once.
- `src-tauri/vendor/isideload/src/auth/apple_account.rs`: if GrandSlam (Apple) itself answers
  -45061 at the init step, Wander discards the anisette (in memory and on disk) and
  provisions again, at most `MAX_GRANDSLAM_REPROVISIONS` = 2 times, so at most 3 init
  requests. The loop lives in `init_with_reprovision`, which runs the init and the
  re-provision through a small `InitSteps` trait so the real loop is tested. Upstream has no
  equivalent for Apple's -45061.
- `src-tauri/src/account.rs`: the existing "Reset Anisette State" action now deletes the
  FsStorage files `anisette_state` and `anisette_state_url` in the app data directory. The
  app defaults to file storage, so the old keyring-only reset did nothing for most users.
  The keyring entries are deleted only when the keyring is the storage in use
  (`keyring_available()`). With the keyring off (the default) nothing reads them, and
  touching them could make macOS ask for the login keychain password, which is the reason
  `secure_storage.rs` avoids the keychain. A keyring error is reported only when no file was
  deleted. The logic is in `reset_anisette_state_in(data_dir, keyring_in_use, delete_keyring)`.
- Tests: `anisette::tests` (retry counter, forced reset, giving up with the typed error,
  cache reuse, `force_reprovision` dropping the cached headers),
  `anisette::remote_v3::tests` (server-marker match, `headers_to_response` for -45061 /
  other errors / data, `select_state` and `save_state` with `InMemoryStorage`: same server,
  other server, no marker, `force_reset`, state in memory),
  `auth::apple_account::tests` (`init_with_reprovision` with scripted GrandSlam replies:
  persistent -45061 stops after 3 inits, one -45061 then success, -80045 fails at once) and
  `account::tests` (files written through `FsStorage` are deleted; keychain untouched with
  the keyring off; keyring error handling).

## 3. Pushed 2FA code (hsc 409) and fresh anisette per step

Mirrors nab138/isideload fdb1788, backported to 0.2.22's simpler 2FA flow.

- `src-tauri/vendor/isideload/src/auth/apple_account.rs`:
  - New `LoginState::NeedsDevice2FAVerification`.
  - The old `trusted_device_2fa` is split into `request_trusted_device_2fa` (the GET to
    `trustedDeviceSecondaryAuth`) and `verify_trusted_device_2fa` (ask the user, then submit
    the code to `validateCode`).
  - `login_state_from_status` handles a reply that has `hsc = 409` and no `au` as "code
    already pushed". The login goes straight to verification, without the GET that would
    cancel the pushed code.
  - Anisette is fetched again after the user has typed the code, in both the trusted-device
    and SMS flows. Before, the one-time password from before the up-to-120-second prompt was
    reused.
- Not applicable: "do not fail the sign-in if listing trusted phone numbers fails". 0.2.22
  never lists trusted phone numbers (SMS still uses phone id 1, as upstream does by default),
  so no lookup exists that could fail. I did not add one, because nothing in Wander's UI
  would use it.
- The post-init login loop is now `drive_login`, which acts through a small `LoginSteps`
  trait (`AppleAccount` implements it via `LiveLogin`). Behaviour is unchanged, including the
  10-step cap, and the account keeps the latest login state also after an error.
- Tests: `auth::apple_account::tests` (409 without `au`, `au` wins over `hsc`, existing `au`
  mapping unchanged, 200 or missing `hsc` means signed in; `drive_login` with a scripted
  account: a pushed code is verified without a new request, trusted-device 2FA requests
  once, SMS, the extra step needs a PET, the loop cap).

## 4. User-Agent, client info and hsc 434 resync

- `src-tauri/src/anisette_patch.rs`: the akd User-Agent is now `akd/1.0 CFNetwork/811.5.4`,
  matching nab138/iloader d319ce7 (2.4.1). The Mac servers report the same CFNetwork build
  plus a `Darwin/16.7.0` suffix. The Mac client-info override stays. Upstream does not
  prefer the server's own client info: iloader 2.4.1 hardcodes the same Mac15,7 string
  through `set_client_info_override` (isideload 20b06c7), with the comment "just temporary
  while waiting for the anisette servers to start reporting this".
- Client info override, mirrors nab138/isideload 20b06c7: `RemoteV3AnisetteProvider` gained
  `set_client_info_override` (`vendor/isideload/src/anisette/remote_v3/mod.rs`). With it
  set, `get_client_info` returns the override and the server's `/v3/client_info` is never
  fetched, also not during provisioning. `src-tauri/src/account.rs` sets it to
  `anisette_patch::akd_client_info()`, as iloader 2.4.1's `account.rs` does. The 2.3.1
  `AkdClientInfoProvider` wrapper is removed: it overrode only the outer client info, so
  the inner provider still had to fetch `/v3/client_info` before it would return headers,
  and a server whose `/v3/client_info` failed could not be used for sign-in. The
  `async-trait` entry in `src-tauri/Cargo.toml` is now unused; it is left in place so
  `Cargo.lock` does not change.
- X-Xcode-Version, mirrors nab138/isideload 232c7f3 and iloader 2.4.1:
  `vendor/isideload/src/auth/grandslam.rs` `base_headers` now sends
  `X-Xcode-Version: 27.0 (27A5218g)` (constant `XCODE_VERSION_HEADER`) instead of
  `14.2 (14C18)` on every GrandSlam request. 232c7f3 introduced the Mac15,7 client info
  Wander already sends together with this value, and upstream HEAD (326e562) still sends it;
  2.3.1 ported only the client-info half. Not tested against Apple.
- hsc 434 resync (nab138/isideload ac8976d): `resync_sim` reads `X-Apple-I-MD-DATA` from an
  init reply with `hsc = 434`. `RemoteV3AnisetteProvider::resync` posts it to
  `/v3/get_headers` (with `sim`, `device_id` and `md_lu`), and the init request is sent once
  more with the corrected headers. As upstream does, the later "complete" step keeps the
  original client-provided data. Files: `vendor/isideload/src/anisette/mod.rs`,
  `.../remote_v3/mod.rs`, `.../auth/apple_account.rs`.
- Test helper: `GrandSlam::test_dummy()` (`#[cfg(test)]`, no network) in
  `vendor/isideload/src/auth/grandslam.rs`.
- Tests: `anisette_patch::tests` (exact client info and User-Agent),
  `auth::grandslam::tests` (X-Xcode-Version, client info and User-Agent headers),
  `anisette::remote_v3::tests` (the override is returned without contacting the server; with
  no override and no server info, headers need provisioning).

## 5. Clear error for -80045, -80046 and -45061

- `src-tauri/src/error.rs`: a new `AppError::AnisetteRejected` (`anisette_rejected`) covers
  `SideloadError::AuthWithMessage` with code -80045, -80046 or -45061. It also covers
  `SideloadError::AnisetteProvisioningExhausted` (the anisette server kept answering -45061),
  matched by type and checked before the generic anisette match so that match does not claim
  it first.
- `src/errors.tsx` and `src/locales/en.json`: new suggestions for that error. They tell the
  user that their Apple ID is not the problem, to sign in again (Wander provisions a fresh
  identity on its own), and, if it keeps happening, to pick another Anisette Server in
  Settings. Other languages fall back to English through i18next `fallbackLng`.
- Tests: `error::tests`. The codes are hard-coded in the test rather than read from
  `ANISETTE_REJECTED_CODES`, and the give-up case uses the real typed error.

## 6. Version

- 2.3.3 in `package.json`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json` and the
  `iloader` entry of `src-tauri/Cargo.lock`. Nothing was tagged, pushed or released.
- `src-tauri/Cargo.toml`: the `[patch.crates-io]` comment now lists the 2.3.3 backports.

## Verification

Run everything with `npm test` (new script in `package.json`:
`bun test tests/ && cd src-tauri && cargo test && cargo test -p isideload`). Plain
`cargo test` in `src-tauri` runs only the app crate's tests: the vendored isideload crate is a
`[patch]` path dependency, not a workspace member, so it needs `-p isideload`. No CI workflow
runs these tests, and `tests/anisette.test.ts` is outside tsc's `include: ["src"]`, so it is
not type-checked by `npm run build` (bun type-strips it when it runs).

- `cargo check --locked` and `cargo check --locked --all-targets` (src-tauri): clean, no warnings.
- `cargo test --locked` (src-tauri, `iloader_lib`): 9 passed.
- `cargo test -p isideload --locked` (vendored crate): 35 passed.
- `npm run build` (`tsc && vite build`, Node 22): passes (only the existing chunk-size warning).
- `bun test tests/`: 16 passed.
- Mutation check on a scratch copy: the review's surviving mutants (M3, M5, M6, M7, M8, M12,
  M13, W3, W5, W6, T3, T5), adapted to the new code, plus new ones for the override, the
  Xcode version and the keychain gate. Results are in the section below.

### Mutation check results

The unmutated copy passed every suite first (9 + 35 Rust tests, 16 bun tests), so each kill
below comes from the mutant. Each mutant is killed by at least one test.

| Mutant | Result |
| --- | --- |
| M3 `force_reprovision` keeps the cached headers | killed |
| M5 stored state reused although the server marker differs | killed |
| M6 a server -45061 becomes a hard error | killed |
| M7 server marker never stored | killed |
| M8 `force_reset` ignored | killed |
| M8b state in memory ignored | killed |
| M12 pushed 2FA code requested again before verifying | killed |
| M13 GrandSlam re-provision counter never increments | killed |
| M15 client-info override ignored | killed |
| M16 X-Xcode-Version reverted to 14.2 | killed |
| M17 give-up error turned back into plain text (replaces the old W3 text-drift mutant) | killed |
| W2 error.rs stops recognising the give-up error | killed |
| W5 reset no longer deletes the file | killed |
| W6 -80046 dropped from `ANISETTE_REJECTED_CODES` | killed |
| W8 keychain touched while the keyring is off | killed |
| T3 `ani.sidestore.io` dropped from the bad list | killed |
| T5 start-up skips the migration | killed |

## Review findings: how each was handled

1. X-Xcode-Version still 14.2 (medium): fixed (section 4).
2. Inner provider still needs `/v3/client_info` (low): fixed by backporting 20b06c7 and
   removing the wrapper (section 4).
3. Legacy Custom servers carried over (low): kept on purpose. The task asked to keep a user's
   own Custom server unless it is known-bad. Probing `{server}/v3/client_info` at start-up
   was not added: it would send a request to an arbitrary user-entered host before the user
   does anything, and the Mac servers' answer only says what they claim, not which ADI they
   run. The risk is documented in section 1, and the failure now shows the
   `anisette_rejected` advice.
4. Inaccurate comments in `anisette_patch.rs` (low): fixed; the module was rewritten.
5. Reset could raise keychain prompts (low): fixed; the keyring is touched only when it is in
   use (section 2).
6. to 13. Missing or tautological tests (M3, M6, M13, M5/M7/M8, the give-up text, the
   rejected-codes loop, the bad-list loop, the three wiring gaps, the FsStorage check): fixed
   with the tests listed in sections 1 to 5. The code under test was moved into small pure
   functions or behind small traits (`headers_to_response`, `select_state`, `save_state`,
   `InitSteps`/`init_with_reprovision`, `LoginSteps`/`drive_login`,
   `reset_anisette_state_in`, `readInitialStoreValues`) so the production code path is the
   one tested.
14. Tests not run by default (low): `npm test` added. CI (`.github/workflows/build.yml`) was
    not changed, to keep the release workflow untouched; adding a test job there is a
    one-line follow-up.
