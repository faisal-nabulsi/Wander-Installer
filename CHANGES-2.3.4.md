# Wander Installer 2.3.4 (unreleased)

Makes Apple ID sign-in harder to break by accident, and explains two install failures that
come from Apple's side. Based on released 2.3.3 (f417bdc). isideload stays at the vendored
0.2.22; one small function in it is fixed (section 7).

Nothing here was tested against Apple's servers or on a device. The new behaviour is covered
by unit tests only. No sign-in and no install was run with the 2.3.4 build.

## 1. One sign-in at a time

Each sign-in asks Apple for a new trusted-device code, and a new code cancels the one before
it. Clicking Login again while "Logging in..." showed therefore made the code the user typed
fail.

- `src-tauri/src/account.rs`: `LoginFlight` holds a single sign-in slot (`LOGIN_IN_PROGRESS`)
  and frees it when dropped, on every return path. A second sign-in started while one runs
  gets the new `AppError::LoginInProgress` (`login_in_progress`) and never reaches Apple.
- `src/AppleID.tsx`: `runLogin` is the one entry point for both "Login" (new account) and the
  stored-account login. A ref blocks a second call made before the next render (a double
  click, or Enter right after a click). The Login buttons are disabled while a sign-in runs,
  and the submit button reads "Logging in...". The Cancel button in the add-account form
  is now `type="button"`, so it no longer submits the form.
- Tests: `account::tests::a_second_sign_in_is_refused_while_one_runs`,
  `stalled_sign_in_times_out_and_frees_the_slot` (also covers section 2).

## 2. Sign-in deadline

Neither HTTP client in isideload sets a request timeout. A server that accepts the connection
and never answers would hold the single sign-in slot, and keep Login disabled, until the app
is quit.

- `src-tauri/src/account.rs`: `single_login_with_deadline` gives the network steps of one
  sign-in `LOGIN_NETWORK_BUDGET` = 90 seconds in total. Time spent waiting for the user to
  type a code is not counted (`UserWait`, filled in by the 2FA prompt). So a stalled server is
  given up on after 90 seconds whether or not a code was asked for, and a code typed late, or
  a second code prompt in the same sign-in, is never cut off. On expiry the sign-in is
  dropped, the slot is freed and the user sees the new `AppError::LoginTimedOut`
  (`login_timed_out`): "The sign-in did not finish in time. Click Login again." The message
  names no server, because the budget also covers the anisette server.
- Why 90 seconds: in the installer log of 2026-11-17 a complete sign-in used about 10 seconds
  of network time. An earlier draft used one 420-second limit for everything (code wait
  included), which kept Login disabled for 7 minutes after a stall. That log holds a real
  stall of this kind (160 seconds with no answer, no code prompt).
- The 2FA prompt itself waits `TWO_FACTOR_TIMEOUT` = 300 seconds (raised from 120 so the help
  steps in section 3 fit).
- `src-tauri/Cargo.toml`: tokio's `time` feature is named explicitly, because the deadline
  needs it. `Cargo.lock` gains no new package.
- Tests: `account::tests::stalled_sign_in_times_out_and_frees_the_slot`,
  `time_spent_typing_codes_is_not_network_time` (two code prompts, each longer than the whole
  budget), `a_stall_after_the_code_still_times_out`.

## 3. Two-factor dialog: help and Cancel

On recent iOS the trusted-device code often does not pop up on its own. The steps to fetch
one by hand are hidden unless the phone is offline, and users were stuck in a dialog with no
way out but to wait.

- `src/AppleID.tsx`, `src/AppleID.css`: the verification-code dialog has a "Didn't get a
  code?" block that opens on click or with Enter/Space. It lists the steps for an iPhone as
  the trusted device (Airplane Mode with Wi-Fi off, Settings > your name > Sign-In &
  Security, Get Verification Code, type the code and turn Airplane Mode off), a line for
  codes sent by text message, and a warning not to press Login again while waiting.
- A Cancel button emits `2fa-cancelled`. `src-tauri/src/account.rs` listens for it and ends
  the sign-in with `AppError::Canceled("Sign-in")`, which shows a short "Sign-in canceled."
  toast, not the error dialog.
- On start-up (and on a page reload) the UI emits `2fa-cancelled` once. A sign-in that was
  left waiting for a code in a dialog that no longer exists then stops and frees the slot.
- Strings are in `src/locales/en.json` only. Other languages fall back to English.
- Test: `tests/locale-fallback.test.ts` (exact English text; every locale falls back).

## 4. Clearer message for -27589

- `src-tauri/src/error.rs`: `SideloadError::AuthWithMessage(-27589, _)` becomes the new
  `AppError::TwoFactorRejected` (`two_factor_rejected`), but only when the report carries
  isideload's "Trusted device 2FA rejected" context, that is, when Apple answered a submitted
  code. From any other step -27589 stays a generic auth error, because "Apple rejected the
  code" would be wrong if the user typed no code.
- The advice: "Apple rejected the code. Close this, click Login once, and enter a fresh
  code."
- Limit: Apple does not document -27589. The mapping rests on one observation on 2026-11-17,
  made while several sign-ins ran at the same time. The likely cause (a code from an earlier
  attempt) is not confirmed.
- Tests: `error::tests::rejected_two_factor_code_gets_its_own_error`,
  `minus_27589_outside_the_code_submission_stays_auth`,
  `login_in_progress_serializes_with_its_own_type`.

## 5. Plain message for Apple's account block (0xe8008024, 0xe8008018)

Since mid-2026 Apple refuses installs signed by some Apple IDs. The phone reports it at
install time, after sign-in and signing have succeeded. Before this version the user saw the
generic "Try again. Restarting the app..." advice, which cannot help.

- `src-tauri/src/error.rs`: new `apple_install_block(text)` recognises the two device
  messages by hex code or by phrase, ignoring case:
  - `0xe8008024` or "The provisioning profile is banned" becomes `AppError::AppleIdBlocked`
    (`apple_id_blocked`).
  - `0xe8008018` or "The identity used to sign the executable is no longer valid" becomes
    `AppError::SigningIdentityRejected` (`signing_identity_rejected`). This code can also
    mean an ordinary revoked certificate, so its advice starts with one more install.
  - A text that holds both codes counts as the banned profile, because that is the specific
    one.
- Where it is checked: on the whole error report text, as the last step before the generic
  `misc` error. The device sends the message inside
  `IdeviceError::ApplicationVerificationFailed`, and matching the whole text also finds it
  if it arrives in another error shape. It runs last so it cannot claim a report that an
  earlier match recognises (for example "maximum number of installed apps").
- `src/errors.tsx`, `src/locales/en.json`: suggestions for both. They are shown in the
  install progress view and in the error dialog.
  - `apple_id_blocked`: "Apple is refusing apps signed with this Apple ID on this device.
    This happens on Apple's side, and people using other sideloading tools report it too.
    Wander cannot fix it." then "Sign out and try a different Apple ID." The first sentence
    says "on this device" because one report has the same Apple ID working on a second
    device.
  - `signing_identity_rejected`: "Apple no longer accepts the certificate that signed this
    app." then "Click Install Wander again. If it repeats, try a different Apple ID." Every
    install already looks up the certificate at Apple and requests a new one when the stored
    one is not listed (`vendor/isideload/src/sideload/cert_identity.rs`), and Sign Out only
    clears the in-memory session, so the advice is a plain retry.
  - Both end with a link to
    `https://wanderspoofer.com/help/install-errors/#apple-id-blocked`.
- English only. Other languages fall back to English.
- Limits:
  - Not reproduced. No blocked Apple ID was available, so the device text in the tests is
    the wording quoted in nab138/iloader issue 583.
  - The help link's `apple-id-blocked` section has been live on wanderspoofer.com since
    2026-11-18.
  - The reports do not show what makes Apple block an account, and none shows a fix for a
    blocked account. The message says Wander cannot fix it instead of suggesting retries.
- Tests: `error::tests::install_block_matches_the_hex_code_or_the_phrase`,
  `install_block_matching_ignores_case`, `banned_profile_at_install_is_apple_id_blocked`,
  `invalid_identity_at_install_is_signing_identity_rejected`,
  `install_block_is_found_outside_the_typed_install_error`,
  `other_install_failures_keep_their_mapping`, and the "Apple account block suggestions"
  group in `tests/locale-fallback.test.ts` (exact English text, fallback in every locale, the
  help link parses as one link).

## 6. Version

- 2.3.4 in `package.json`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json` and the
  `iloader` entry of `src-tauri/Cargo.lock`. Nothing was committed, tagged, pushed or
  released.

## 7. A crash during sign-in no longer leaves Login stuck

Tauri sends no reply for a command that panics, so the UI kept showing "Logging in..." with
Login disabled until the app was restarted.

- `src-tauri/src/account.rs`: `single_login_with_deadline` catches a panic inside the sign-in
  and returns an ordinary error ("The sign-in stopped because of an internal error."). The
  panic text is not copied into the message, because it can quote what the user typed.
- `src-tauri/vendor/isideload/src/auth/apple_account.rs`: `censor_email` (called at the start
  of every sign-in, for the log) sliced the Apple ID by byte. It panicked when the part before
  the @ was empty or began or ended with a non-ASCII letter (for example an address typed
  with a Cyrillic keyboard layout). It now works by character. Output for ordinary addresses
  is unchanged.
- Tests: `account::tests::a_panic_in_the_sign_in_becomes_an_error_and_frees_the_slot`,
  isideload `auth::apple_account::tests::censor_email_keeps_its_output_and_never_panics`.

## Before releasing

1. Publish the `apple-id-blocked` section of the help page first (section 5).
2. Open the built app once and, with your own Apple ID: sign in and type a 2FA code; press
   Cancel in the code dialog, then Login again; sign in from a saved login; sign out and sign
   in; double-click Login. This needs your password and a code from your phone. About 5
   minutes. It is the only test of the new sign-in path against Apple.

## Verification

Run on 2026-11-17 on macOS (Apple Silicon), with
`CARGO_TARGET_DIR=src-tauri/target-234`.

- `bun install --frozen-lockfile`: no changes to `bun.lock`.
- `bun test tests/`: 23 passed, 0 failed (2 files).
- `bunx tsc --noEmit`: clean.
- `bun run build` (`tsc && vite build`): passes (only the existing chunk-size warning).
- `cargo test --locked` (src-tauri, `iloader_lib`): 23 passed, 0 failed.
- `cargo test --locked -p isideload` (vendored crate): 36 passed, 0 failed.
- `cargo check --locked --all-targets`: clean, no warnings.
- `rustfmt --check` on `src-tauri/src/error.rs`: clean. `src-tauri/src/account.rs` has two
  formatting differences that are already in 2.3.3; they were left alone.
- Mutation check on the deadline: with the code-wait subtraction removed,
  `time_spent_typing_codes_is_not_network_time` and `a_stall_after_the_code_still_times_out`
  fail.
- Mutation check on the new matcher (each mutant applied to `error.rs`, tests run, file
  restored): phrase needle for the banned profile removed, case folding removed, either hex
  needle removed, whole-report check removed. Each one fails at least one test.
- Local macOS app bundle (Apple Silicon, ad-hoc signed, not notarized):
  `bun tauri build --bundles app --config '{"bundle":{"createUpdaterArtifacts":false}}'`.
  The override only skips the updater archive, which needs the release signing key. That key
  was not used or read. The app keeps the release updater public key and endpoint.
  - `Info.plist` reads 2.3.4 for `CFBundleShortVersionString` and `CFBundleVersion`.
  - The binary contains the matcher text ("the provisioning profile is banned",
    "0xe8008024", "0xe8008018") in plain form.
  - The frontend is stored brotli-compressed inside the binary. The compressed bundle from
    the build directory is present in the binary byte for byte. Decompressed, it equals
    `dist/assets/index-*.js` and contains "Didn't get a code?" and both new suggestions.
  - Launch check: the app was started once in the background, ran for 25 seconds and was
    quit. Its log shows the update check (latest release 2.3.3, so no update offered) and the
    device list read, and no panic. No window was looked at and nothing was clicked. No
    sign-in was started.

Not verified:

- No sign-in and no install was run with this build, on any platform.
- The Apple account block was not reproduced (section 5).
- Windows and Linux builds were not made.
- The release build with updater artifacts (the CI path) was not run.
